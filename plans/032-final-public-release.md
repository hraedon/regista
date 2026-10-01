# Plan 032 — A focused work-coordination MVP for Regista

> **0.8.0 disposition: CURRENT.**
> Release line this plan describes: the governing plan for the 0.8.0 release — the work-coordination MVP scope reset this entire disposition pass implements.
> Why: this is the plan being executed, not a historical artifact; every other marker in `plans/` cites it as the authority for its disposition.
> See `plans/032-plan-dispositions.md` for the full disposition index and `plans/032-final-public-release.md` for the 0.8.0 reduction these dispositions follow.

**Status:** Draft. The owner has authorized planning around substantial simplification and breaking changes; the current request is for a plan, not implementation or publication.  
**Date:** 2026-09-04.  
**Baseline:** main `7707c81`, package version `0.7.2`.  
**Recommended release:** `0.8.0`, an explicitly breaking scope reset delivering a complete, bounded MVP, followed by maintenance. Confirm at release preparation; do not declare 1.0 merely to signal closure.

## 1. Decision and product

Owner clarification: **“there are effectively no current users, so if it makes sense to bludgeon regista back to the original design, that's fine.”**

This replaces the initial plan's emphasis on preserving the published feature surface and qualifying upgrades from every version. The owner subsequently asked for a useful niche, not just an orderly retirement. The product proposition is:

> An embeddable work-coordination ledger for Python applications: durable ownership, validated handoffs, and replayable history across independent workers and people.

The target user already has scripts, workers, agent processes, or a human-facing application running elsewhere and needs shared answers to: who owns this work, what state is it in, what may happen next, and how did it get here? Regista owns coordination state; callers own execution and their interfaces. Register a workflow, create work, claim it, make validated transitions, query state, and recover after restart or restore. Events and current projections commit atomically. Ordinary use requires neither agent-suite nor trust-genesis/key-governance ceremonies.

The MVP is agent-friendly, not agent-specific. It is not a job executor, durable-code-execution engine, scheduler, hosted tracker, or human UI. DBOS already offers PostgreSQL-backed durable workflows, Temporal durable execution, and Procrastinate PostgreSQL task queues. Regista's proposed niche is explicit work ownership and handoffs among independently running participants; it is not a claim that those tools cannot model the same problems. “Python plus PostgreSQL” alone is not differentiation. References checked 2026-09-04: [DBOS architecture](https://docs.dbos.dev/architecture), [Temporal documentation](https://docs.temporal.io/), [Procrastinate documentation](https://procrastinate.readthedocs.io/en/stable/).

Demand remains unproven. The two public-API examples in F0a are the first product-fit check, not evidence of market adoption. Their result must inform the API before broad removal work.

“Original design” means the original useful boundary, not a blind revert to an old commit. Preserve later fixes to concurrency, transaction handling, idempotency, canonicalization, and error reporting where they serve the retained kernel.

The final contract trusts the host application and database administrators. Actor IDs are caller-supplied attribution. Workflow role checks enforce application policy; they do not independently authenticate people or agents. Replay detects inconsistency and reconstructs supported state; it does not establish hostile-administrator tamper evidence, non-repudiation, model identity, or external freshness.

Deliver a complete release with a bounded maintenance policy, without declaring the product permanently finished before anyone tries the clarified purpose. No feature-expansion commitment is implied. Later changes must serve this niche and be justified by concrete usage; the old suite roadmap does not resume automatically.

Lease protection stops a stale worker from committing protected changes to Regista. It does not stop that process from making external requests or changing another system. Expose the claim attempt/fencing value through the public API and require it for lease-protected mutations. Explain external-effect idempotency and target-enforced fencing separately; do not claim exactly-once effects or automatic process termination.

## 2. Starting evidence and constraints

- PyPI metadata checked 2026-09-04 reports `regista-hraedon` latest `0.7.2`, with releases 0.5.1–0.5.5, 0.6.0, and 0.7.0–0.7.2, none yanked. Source: <https://pypi.org/pypi/regista-hraedon/json>. Recheck before publication. Import and executable names are `regista`.
- Main contains the ordinary v6 writer and post-0.7.2 bundle/trust-log work. Some README/changelog descriptions are stale. Earlier audit findings are not automatically current.
- The tracker includes landed-but-open work, active defects, and abandoned ambitions. Reconcile by retained responsibility rather than trying to empty the backlog.
- Metadata advertises Python >=3.11; ordinary CI runs 3.13/3.14 and publication verification runs 3.14. Align the advertised and tested range.
- Existing edits to `tests/test_retired_tests_ledger.py` and `tests/test_wi289_cluster4_ledger_mapping.py` belong to other work. Preserve them and identify ownership before overlapping implementation.
- Effectively no users permits a deliberate compatibility break, not accidental data destruction. Unknown downloads remain possible: explain the break and refuse old schemas before any mutation. No migration programme is required.
- This implementation must not modify the live private estate, uninstall its tools, or rewrite repository history.

## 3. Target scope

### Keep and qualify

| Responsibility | Contract |
| --- | --- |
| PostgreSQL namespace | Retain schema-per-project initially, explicit configuration, scoped transactions, bounded pool behavior. No tenancy-model rewrite. |
| Workflows | Immutable registered versions, work-item version pinning, validated states/transitions/roles/required fields; straightforward YAML/JSON Schema support. |
| Work items | Public create/query/transition paths with stable IDs and typed results/errors. Bounded, predictably ordered queries for available, owned, blocked, and review-ready work using workflow-defined states and claim facts. |
| Claims | Durable leases, heartbeat, expiry/takeover, and stale-attempt refusal under concurrency. |
| Events and projection | Atomic append plus current-state update, ordered history, replay of supported state with honest drift reporting. |
| Idempotency | Identical retries do not duplicate effects; conflicting key reuse refuses. |
| Custom fields | Basic validated domain data and bounded filtering; callers can describe work without modifying Regista. No new schema language. |
| Typed links | Explicit relationships between items with simple lookup and validation. Links describe relationships; they do not introduce a dependency scheduler. |
| Administration | Small initialization/workflow/inspection/replay/health CLI and PostgreSQL backup/restore documentation. |

Custom fields and typed links are required MVP features. Keep their semantics small and documented. “Blocked” and “review-ready” are queries over a caller's workflow, not a mandatory canonical workflow or inferred scheduling policy. The library and CLI must expose the same useful coordination operations; no HTTP service is required for a person to participate through the example CLI.

### Remove by default

- Trust domains, root/registrar governance, principal custody, key lifecycle ceremonies, action-delegation credentials, and estate catalogs.
- v6 cryptographic admission prerequisites, audit bundles, witness/anchoring machinery, and cryptographic genesis/release gates.
- Model-lineage registries, built-in assurance classification, and canonical agent-suite review policy. Generic workflows can have review states without identifying models.
- Suite configuration discovery, lock/health dependencies, cross-component provisioning, and sibling private-API imports.
- Field encryption/custody integrations serving the removed evidence system. Storage/database encryption becomes an explicit operator responsibility.
- Recurrence scheduling, async hooks/webhook delivery, witness maintenance, and workflow inheritance unless F0 identifies a small independent subset worth retaining. Default to removal rather than keeping machinery because it has tests.
- The HTTP sidecar as a supported deployable, unless F0 demonstrates a thin pass-through with bounded qualification cost and the maintainer selects it. Avoid retaining a second authentication/deployment product by inertia.

Keep the in-memory backend only if it shares actual transition/reduction rules and accurately states its missing durability/concurrency guarantees. Otherwise retire it and use disposable PostgreSQL fixtures. Do not maintain a second engine solely for test convenience.

### Signing

Recommended default: remove signing as a prerequisite and omit cryptographic verification from the supported contract. Canonical serialization and consistency checks may remain. Unkeyed hashes must never be presented as authenticity evidence.

Do not restore server-held per-actor keys and call them non-repudiation. If a small optional HMAC facility is retained, it must be independent of ordinary use and describe only integrity relative to possession of a shared secret. It must not pull trust governance or bundle infrastructure back into scope. Settle this in F0; deletion is the default.

## 4. Work packages

Track execution in Regista's existing tracker. These labels are planning references, not a replacement issue store. Record exact commits and evidence on execution items.

### F0 — Freeze the smaller contract and deletion map

Deliver a concise revised spec, public-surface keep/delete table, dependency map, and baseline regression inventory.

1. Read original specification/history for intent; write final requirements in present tense. Explicitly reconcile `spec.md`, its sidecar, and AGENTS.md. Mark the 0.6 trust design and affected plans historical for the new release. Do not leave competing normative instructions.
2. Trace the current public create → claim → transition → replay path. Identify trust/signing/suite dependencies. Select corrected current code or historical implementations per responsibility; never select an entire old release just because it is smaller.
3. Map deletions through imports, public facades, CLI, schemas, dependencies/extras, packaging, tests, examples, and docs. Record any exception to the default removals and its qualification cost.
4. Reconcile retained tests and existing ledger edits with their owner. Retire deleted-feature tests with explicit dispositions; preserve regression protection for defects that can survive in the kernel. Historical coverage totals are not release requirements.
5. Choose Python/PostgreSQL support. Prefer retaining the advertised minimum if feasible; otherwise deliberately change metadata and notes. No new provider/platform qualification programme.

Exit: a provisional smaller contract, bounded deletion/qualification checklist, and the proposed public API needed by F0a. F0a must validate that API before broad deletion begins.

### F0a — Validate the niche with two executable examples

**Dependencies:** F0. **Deliverables:** two runnable examples, documented proposed API, and a short product-fit report. This precedes broad F1 removal, not all code changes: a minimal isolated PostgreSQL-backed implementation or extraction may be needed to exercise the proposed contract. It must become the retained implementation, not a throwaway second engine. No mocks or private imports may stand in for the claimed coordination behavior.

1. **Worker and reviewer handoff.** A discovery script creates remediation work with domain fields and a typed link. Two independently running worker processes contend for it; only one owns the attempt. A worker records a result and hands it to a reviewer using the CLI. The reviewer requests changes; a worker takes another attempt. Terminate that worker, allow its lease to expire, and demonstrate takeover plus rejection of a stale mutation carrying the old attempt. Finish through a fresh review and display the resulting history. Workers may be deterministic scripts: this validates agent-compatible coordination, not an LLM's behavior.
2. **Non-agent document processing.** An ingestion script creates a document item with a source reference and links a follow-up item. A processing worker records extracted fields, a person corrects or rejects them through the CLI, and a worker completes the approved item. Query available, owned, blocked, and review-ready work throughout. Use the same public API and schema baseline with a different workflow and field definitions; add no document-specific code to Regista.

Both examples must run from documented commands against disposable PostgreSQL without suite configuration, keys, private modules, or application-specific patches to the library. Include a small external-effect example using a stable operation/idempotency key and explicitly identify which duplicate protection belongs to the downstream application. Do not imply a Regista lease makes an external effect exactly once.

Measure setup commands/prerequisites, time to first completed item in a recorded clean run, required application glue, and any surprising refusals or private-API temptations. A reviewer unfamiliar with the implementation must be able to follow the quickstart unaided; record where they needed clarification. Avoid arbitrary API line-count targets and unsupported usability claims.

**Exit:** both scenarios fit naturally through the proposed public surface, ownership/handoff failures are understandable, and the report explains the benefit over bespoke state/claim tables. Revise the API if they do not fit. If they only work by introducing a scheduler, execution engine, or suite-specific policy, narrow the product before proceeding. These examples remain release acceptance cases in F3.

### F1 — Remove expanded dependencies and establish a fresh baseline

**Dependencies:** F0a product-fit exit. Promote its minimal implementation into the kernel and remove superseded paths; do not rebuild the example API separately.

Work in an isolated worktree. Preserve a local reference to the pre-reduction source before large deletions; do not rewrite history.

- Replace trust-dependent admission with the documented smaller library boundary while retaining validation, ordering, idempotency, and rollback. This is an explicit contract change, not an undocumented bypass of security checks.
- Establish a fresh, clearly versioned schema baseline. No chain of migrations through trust-system schemas is required. Initialization/open must distinguish supported new schemas, empty destinations, and old/unknown schemas. Refuse unsupported schemas before writes; never automatically drop or reset them.
- Preserve one implementation of transition and reduction rules. Remove dead callable paths, not just documentation. Old methods/commands must fail clearly rather than silently acquire a different meaning.
- Remove dependencies and CI requirements belonging only to deleted features. Wheels/sdists must not accidentally ship retired implementations as alternate entry points.
- Make a minimal public example work: connect/init → register → create → claim → transition → query. No keys, trust log, suite configuration, or private-module bootstrap.

Exit: a fresh database supports the kernel without the removed stack; old databases remain untouched.

### F2 — Harden retained behavior

Required evidence against real PostgreSQL:

- Atomic event/projection updates, including failure between effects; replay reconstructs the same supported state.
- Correct serialization, sequence allocation, optimistic checks, and lock ordering under contention.
- Claim takeover invalidates stale attempts; heartbeat/release and lease-protected result/transition writes cannot affect a replacement lease. Public callers supply the expected attempt/fencing value. Expiry tests do not rely on fixed calendar dates.
- Identical request retries are idempotent; conflicting reuse refuses without partial effects.
- Invalid workflows/transitions/fields and disallowed application roles produce stable refusals.
- Project scoping and database permissions match the documented deployment; supplied names cannot redirect operations outside the namespace.
- Bounded health/pool behavior, interruption handling, and useful replay errors. Reasonable history sizes remain practical to query/replay.
- Required typed links, custom fields, and work-discovery queries match their explicit contracts, including pagination/order and invalid field/link refusals. Any retained in-memory backend states its limits accurately.
- Generic review/repair handoffs remain possible after ordinary revisions, without model-family policy or historical identity metadata making an item permanently unreviewable.

Use tracker items as seeds. Operational items such as WI-247/260/328/341 may survive. Trust/custody/bundle/assurance items such as WI-331/338/342/344/351–362 require residual-reachability checks after removal, not automatic repair beforehand. Mark removed-feature issues as removed from the new release, never as fixed in old versions. Repair any retained path affected by the same finding.

For fixes, demonstrate meaningful regression failure before and success after where applicable. For deletions, verify absent dependencies/entry points and a working core path. Follow repository independent-review requirements. Use isolated synthetic fixtures; do not exercise defects against the live estate.

Exit: no known unresolved defect contradicts the retained coordination, isolation, or recovery contract. No requirement to harden code that no longer ships.

### F3 — Qualify distribution, restart, and recovery

Use clean environments without sibling checkouts or private configuration.

1. Install the built `regista-hraedon` wheel and exercise import/CLI. Build/install from the sdist too; verify schema resources are included.
2. Run both F0a examples verbatim from the installed package, including the two-process race, reviewer repair loop, crash/takeover, and stale-attempt refusals. Verify work-discovery queries, fields, and links. Restart and read persisted state.
3. Exercise replay, rollback, and contention on PostgreSQL.
4. Dump a populated database, restore separately, reconnect, replay, and perform another valid write. A successful verifier alone does not prove usable recovery.
5. Present representative 0.5-era and 0.6/0.7-era schemas: the new initializer/opener must refuse without mutation. No per-version upgrade matrix is required because in-place upgrades are unsupported.
6. Run required lint, type checks, retained tests, and relevant scale checks across the declared support matrix. Review exclusions by retained behavior, not historical counts.

Exit: an installed artifact supports documented operation and recovery. Record artifact hashes, environment versions, commands, and sanitized results.

### F4 — Document the deliberate scope break

- Rewrite README, current API/CLI docs, spec, examples, and changelog around coordination. Explain attribution, role checks, replay, and the trusted-host/database-admin boundary.
- Lead with the ownership/handoff proposition, `pip install regista-hraedon`, and a short tested example. Link the full F0a scenarios. Explain when a task queue or durable execution engine is a better fit; avoid asserting uniqueness or demonstrated demand. Remove disabled bootstrap machinery and unfinished phase narratives from current guidance.
- List removed APIs/commands/extras/formats and the fresh-database requirement. No supported in-place upgrade from 0.7.2 or earlier. Preserve distribution/import naming unless a concrete packaging conflict requires otherwise.
- Provide a short preservation procedure: retain the old dump, matching package/dependency environment, and any old keys/trust material; verify a scratch restore before changing anything. Historical readers retain their known limitations. No converter, regenerated audit claim, or AOS migration is required.
- State bounded MVP scope, reporting routes, and the actual maintenance commitment. Suggested option: a 90-day stabilization window for release regressions and serious security/data-loss reports, without promised new features or an SLA. Invite concrete usage feedback without committing to a roadmap. The maintainer chooses before publication; no indefinite commitment is assumed.

Exit: public claims match the small product, and prior published versions have clear preservation guidance without a migration project.

### F5 — Prepare and publish when authorized

- Obtain final independent review of the kernel/removal boundaries and remote CI at the exact candidate.
- Check metadata, dependency set, packaged files/schema resources, README rendering, and support/version declarations.
- Prepare version, release notes, maintenance notice, and reviewed wheel/sdist artifacts. Publish the same qualified bytes; if tag automation rebuilds, qualify that build or prove equivalence.
- The current `v*` tag workflow publishes to PyPI. A tag push is publication, not bookkeeping. Obtain explicit owner authorization before pushing the release tag, uploading, announcing, publishing advisories, or yanking versions. Prepare everything first.
- Do not automatically delete or yank older releases. Any such action needs an affected-version assessment and separate decision.
- After authorized publication, verify public metadata/digests and install from PyPI in a fresh environment before declaring completion.

## 5. Scope budget and finish line

Measure successful public workflows and adoption friction alongside removed executable subsystems, runtime dependencies, and required setup steps. Fewer lines alone do not establish a useful product. Moving or renaming the old machinery is not simplification.

No trust-domain repairs before deciding whether their code ships. No compatibility migration programme, new adapter framework, or completion of the old suite roadmap. Refactor the retained kernel only where the contract or removal requires it.

If severing trust dependencies requires replacing most of the kernel, produce the dependency evidence and compare extracting the corrected kernel into a fresh package tree in this repository with retaining a smaller current path. Substantial simplification is allowed; choose on final complexity and qualification cost rather than sunk effort.

Release checklist:

- [ ] One small authoritative contract and explicit trust boundary.
- [ ] Worker/reviewer and non-agent scenarios validate the same public API before broad deletion.
- [ ] Useful discovery queries, basic custom fields, and typed links are supported.
- [ ] Public lease fencing and external-effect limitations are documented and demonstrated.
- [ ] Removed features absent from packaged/callable surfaces and current claims.
- [ ] Ordinary operation requires no suite or cryptographic ceremony.
- [ ] Transaction, replay, claim, idempotency, and scoping invariants qualified.
- [ ] Installed quickstart, restart, and usable restore pass.
- [ ] Old schemas refuse without mutation; preservation guidance exists.
- [ ] Documentation, metadata, version support, and maintenance statement agree.
- [ ] Final artifacts, CI, and independent review pass.
- [ ] Publication authorized and public-index installation verified.

Stop this implementation programme when these pass and move to the declared maintenance posture. Consider future features only against observed use of the coordination niche; there is no obligation to expand. Supersede old roadmap items through the tracker; do not turn them into release dependencies. Keep AOS independent.

Drafting validation: current source/metadata, publication workflow, historical plans, public PyPI metadata, and tracker titles were inspected. No runtime fixes, security revalidation, data migration, or release qualification were performed while drafting.
