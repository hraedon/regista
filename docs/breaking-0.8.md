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
suite discovery are removed. Unknown commands refuse via the CLI parser. Only
`dev` remains as an optional dependency extra; all old feature extras are gone.
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
