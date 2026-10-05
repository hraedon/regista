# 0.8.0: breaking, deliberate scope reduction

The distribution remains `regista-hraedon`; import and executable names remain
`regista`. The public library surface is exactly `regista.__all__`, documented in
[api.md](api.md). The complete supported command list is in [cli.md](cli.md).
No old name silently acquires the new semantics.

**A fresh database is required. No in-place upgrade from 0.7.2 or earlier is
supported.** Old migration markers, signed events, trust-dependent schemas and
unknown occupied destinations refuse without mutation. There is no converter,
reset, or automatic project removal. Preserve first using [operations.md](operations.md).

| Removed or changed | 0.8.0 contract |
| --- | --- |
| `Regista`, `InMemoryRegista`, `AsyncRegista`, `AsyncInMemoryRegista`, old facade namespaces/result shapes | `Kernel`, PostgreSQL only; typed public results and errors |
| Library signing/verification, HMAC/Ed25519 schemes, principal/key enrollment/custody/lifecycle, trust domains/registrars/root governance, action delegation | Caller attribution and trusted-host role assertions; unkeyed consistency hashes only |
| Bundle v1/v2/v3, signed envelope v2–v6 readers/writers, trust-log exports, estate catalogs, witness receipts, anchoring/timestamp proofs | No old format reader/converter or audit authenticity claim |
| Generic signed spec/entity model, suite configuration/secrets resolvers, canonical suite workflow, model-lineage/assurance policy | Work items and caller workflows only; explicit connection configuration |
| Field encryption/custody, Vault/Azure and crypto dependencies/extras | Database/transport/storage protection is the operator's responsibility |
| HTTP sidecar and `sidecar` extra; suite-conformance/deployable service machinery | Embed the library or use the CLI; no HTTP server |
| Recurrence, async hooks/webhooks/queues, synchronous validators/callback registration, automatic escalation, workflow `extends` composition | Callers own execution, scheduling and pre-transition validation; required-field, role and field-type checks remain |
| Lease auto-release during transition in 0.7 | **Leases are retained through transitions until explicit release**, including terminal states (ruling 2026-10-05) |
| Old CLI `replay` projection rebuild | `check-history` is read-only; old command explicitly refuses |
| Background maintenance thread and metrics exporter | Operator schedules `expire-leases`; no scheduling or metrics service |
| Project catalog/drop/unregister, service-role provisioning/dry-run/CREATEROLE diagnostics | Operator creates service roles and manually uses `DROP SCHEMA` for deletion |
| Cross-project links, value references, content hashes and link annotations | Typed links between existing items in the same namespace; optional source-workflow vocabulary |
| Actor-role registry, actor/link metadata, old event IDs, wildcard idempotency lookups, history actor/time filters, whole-project event tail | Caller role assertions, basic JSON fields/payloads, create/transition request keys, bounded per-item history |
| Nested containment filters, deferred `not_before`, workflow/library startup compatibility policy | Eight top-level scalar-equality filters; no scheduling; one fresh schema baseline |

Old administration commands for provisioning, project catalogs, trust/signing,
principal lifecycle, witness/anchors, bundles, hooks, recurrence, sidecar, and
suite discovery are removed. Unknown commands refuse via the CLI parser. Removed extras are **`sidecar`, `ed25519`, `encryption`, `vendor-check`, `vault`,
`azure`, and `windows`**. Only `dev` remains; its suite-conformance dependency is
also retired.
The workflow format is `kernel_workflow: 1` and its JSON Schema ships in the
package; it is separate from both registry versions and the kernel schema version.
The old machine-readable `spec.yaml` sidecar is retired.

Inputs enforce UTF-8 byte bounds: fields and transition payloads each 64 KiB,
workflow documents/definitions 256 KiB, ordinary names 255 bytes, schemas 63 bytes.
JSON nesting is at most 32. Values must be JSON-compatible and finite; field clears
are explicit and shallow merge replaces nested objects wholesale. Query pages
are 1–500 rows (default 50), state/name sets cap at 500, field filters at eight;
replay drift caps at 100 diagnostics plus an omission summary. Old unlimited or
implicitly coercing input behavior is unsupported.

Leases, attempt counters, typed links and idempotency keys are projection-only
and explicitly outside replay coverage. Preserve them through whole-database
backup; no supported replay rebuild exists. See the trust/recovery limitations
in [operations.md](operations.md). Retiring a vulnerable subsystem does not fix
any older release that shipped it.

## Mechanically generated 0.7.2 → 0.8.0 inventory

Generated from `84bb2ec:src/regista/__init__.py`, its complete CLI parser
and the current root/parser by `scripts/generate_removal_inventory.py`.
The [complete machine-readable comparison](breaking-0.8-inventory.json)
also lists every added name/path. Retained spelling does not preserve the
old contract.

### Old public root names

| Name | 0.8.0 disposition |
| --- | --- |
| `ActionDelegationCredential` | removed |
| `ActionDelegationError` | removed |
| `ActionDelegationScope` | removed |
| `ActorKind` | removed |
| `ActorMetadata` | removed |
| `ActorRole` | removed |
| `Applicability` | removed |
| `Approval` | removed |
| `ApprovalVerifier` | removed |
| `AssuranceLevel` | removed |
| `AuthorizationEvidence` | removed |
| `BundleReferents` | removed |
| `ChallengeStorageScope` | removed |
| `Claim` | retained name; changed kernel contract |
| `ConnectionInfo` | removed |
| `CustodyMode` | removed |
| `DeadLetterEntry` | removed |
| `DelegationVerificationStatus` | removed |
| `EffectiveReceipt` | removed |
| `EffectiveReceiptStatus` | removed |
| `EnrollmentRequest` | removed |
| `EnvelopeVersion` | removed |
| `ErrorCode` | removed |
| `Event` | retained name; changed kernel contract |
| `GateProfile` | removed |
| `GenesisRecovery` | removed |
| `HookContext` | removed |
| `LifecycleAuthority` | removed |
| `LifecycleAuthorityKind` | removed |
| `LifecycleContractError` | removed |
| `LifecycleDigest` | removed |
| `LifecycleErrorCode` | removed |
| `LifecycleOperation` | removed |
| `LifecycleOperationType` | removed |
| `LifecycleState` | removed |
| `LineageRelation` | removed |
| `Link` | removed |
| `MODEL_LINEAGE_FAMILIES` | removed |
| `NO_REFERENTS` | removed |
| `PossessionChallenge` | removed |
| `PossessionProof` | removed |
| `PrincipalDescriptor` | removed |
| `PrincipalKind` | removed |
| `PrincipalLifecycle` | removed |
| `Producer` | removed |
| `ProjectCatalogEntry` | removed |
| `ProofFormat` | removed |
| `QueryPage` | removed |
| `REGISTA_VERSION` | removed |
| `ReconciliationReport` | removed |
| `ReconciliationStatus` | removed |
| `Regista` | removed |
| `RegistaError` | removed |
| `RegistryReceipt` | removed |
| `RegistryReceiptStatus` | removed |
| `ReplayReport` | removed |
| `ReplayReportEntry` | removed |
| `RevocationRequest` | removed |
| `RotationRequest` | removed |
| `TrustLogVerificationReport` | removed |
| `V6GenesisWrite` | removed |
| `ValidationError` | removed |
| `ValidationResult` | removed |
| `VerificationPolicy` | removed |
| `VerificationResult` | removed |
| `VerifiedActionDelegation` | removed |
| `VersionInfo` | removed |
| `WorkItem` | retained name; changed kernel contract |
| `WorkflowDefinition` | removed |
| `WorkflowVersion` | removed |
| `action_delegation_hash` | removed |
| `bundle_referents` | removed |
| `canonical_lifecycle_digest` | removed |
| `canonical_workflow_yaml` | removed |
| `chain_head_hash` | removed |
| `compose_workflow` | removed |
| `compute_assurance_level` | removed |
| `config` | removed |
| `gate_rationale` | removed |
| `lineage_relation` | removed |
| `make_verification_policy` | removed |
| `parse_action_delegation` | removed |
| `parse_and_validate` | removed |
| `parse_file` | removed |
| `parse_workflow_yaml` | removed |
| `resolve_producer` | removed |
| `same_lineage` | removed |
| `secrets` | removed |
| `validate_principal_id` | removed |
| `validate_yaml` | removed |
| `verify_event_with_referents` | removed |
| `versions` | removed |

### Old full command tree

| Full path | 0.8.0 disposition |
| --- | --- |
| `actor-roles` | removed |
| `actor-roles list` | removed |
| `assurance` | removed |
| `bundle` | removed |
| `bundle export` | removed |
| `bundle verify` | removed |
| `config` | removed |
| `doctor` | removed |
| `events` | removed |
| `events archive` | removed |
| `events show` | removed |
| `events tail` | removed |
| `genesis` | removed |
| `genesis init` | removed |
| `hooks` | removed |
| `hooks dead-letter` | removed |
| `hooks dead-letter list` | removed |
| `hooks dead-letter requeue` | removed |
| `invariants` | removed |
| `invariants probe` | removed |
| `keys` | removed |
| `keys adopt-enrollment` | removed |
| `keys fingerprint` | removed |
| `principal` | removed |
| `principal enroll` | removed |
| `principal list` | removed |
| `principal register` | removed |
| `principal resolve-backend-name` | removed |
| `principal revoke` | removed |
| `principal rotate` | removed |
| `provision` | removed |
| `provision-principal` | removed |
| `recurrence` | removed |
| `recurrence cancel` | removed |
| `recurrence due` | removed |
| `recurrence fire` | removed |
| `recurrence list` | removed |
| `recurrence update` | removed |
| `replay` | removed |
| `schema` | removed |
| `schema init` | removed |
| `schema repair-checksums` | removed |
| `schema status` | removed |
| `secrets` | removed |
| `signer` | removed |
| `signer generate` | removed |
| `signer sign-effective` | removed |
| `signer sign-possession` | removed |
| `spec` | removed |
| `spec events` | removed |
| `spec sign` | removed |
| `trust` | removed |
| `trust catalog` | removed |
| `trust delegate-registrar` | removed |
| `trust enroll` | removed |
| `trust init-log` | removed |
| `trust publish-log` | removed |
| `trust rebuild-projection` | removed |
| `trust sign-catalog` | removed |
| `trust sign-genesis` | removed |
| `trust sign-log` | removed |
| `trust verify-catalog` | removed |
| `trust verify-genesis` | removed |
| `trust verify-log` | removed |
| `version` | removed |
| `webhook` | removed |
| `webhook list` | removed |
| `webhook register` | removed |
| `webhook remove` | removed |
| `witness` | removed |
| `witness deliver` | removed |
| `witness list` | removed |
| `witness receipts` | removed |
| `work-item` | removed |
| `work-item create` | removed |
| `work-item list` | removed |
| `work-item show` | removed |
| `work-item transition` | removed |
| `workflow` | retained spelling; changed kernel format/contract |
| `workflow compose` | removed |
| `workflow validate` | retained spelling; changed kernel format/contract |

### Intentional implementation bindings

These bindings in the old root implement the facade or support imports;
they are not deliberate API re-exports. Underscore names are private.
They are tracked separately, including `_config`; its public alias `config`
appears in the API table above.

`Any`, `ArchiveOps`, `AssuranceOps`, `AsyncApiMixin`, `Callable`, `ClaimApiMixin`, `ClaimOps`, `ConnectionManager`, `EventOps`, `ExternalApiMixin`, `GenesisApiMixin`, `HookOps`, `KeySet`, `LinkOps`, `MetaApiMixin`, `Metrics`, `PrincipalKeyOps`, `RecurrenceOps`, `TracebackType`, `WebhookOps`, `WitnessOps`, `WorkItemOps`, `WorkflowApiMixin`, `WorkflowOps`, `_load_trust_genesis_document`, `_sys`, `_trust_genesis_path_from_env`, `annotations`, `check_integrity`, `log`, `run_migrations`, `structlog`
