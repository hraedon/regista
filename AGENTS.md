# Regista — Agent Guide

> **0.8.0 scope reset (2026-09-11):** regista was reduced to its general
> work-coordination kernel — an embeddable ledger for durable ownership,
> validated handoffs, and replayable history over PostgreSQL. Signing/keys, trust
> domains, principals/custody, audit bundles, witnesses, hooks/webhooks,
> recurrence, lineage/assurance/review policy, suite configuration, encryption,
> the HTTP sidecar, and the in-memory backend were **removed**. There is **no
> supported in-place upgrade** from 0.7.2 or earlier. See
> `plans/032-final-public-release.md`, `plans/032-f0-contract-reduction.md`, and
> `CHANGELOG.md`. Pre-0.8.0 specifications and design records live under
> `docs/history/` and are historical, not normative.

## Project Overview

Regista is a Python library providing coordination and durable state for work
shared across independently running workers and people. It implements an
event-sourced model with a transactionally-consistent denormalized projection,
durable leases, and validated workflow handoffs, over PostgreSQL.

`spec.md` is authoritative for the reduced kernel; `spec.yaml` is its
machine-readable sidecar. The spec is amendable when implementation reveals it
cannot deliver a stated guarantee — amend deliberately with a breadcrumb
resolution note explaining the change; do not silently diverge.

**Product boundary:** regista owns coordination state (who owns work, what state
it is in, what may happen next, how it got here). Callers own execution and their
own interfaces. It is not a job executor, durable-execution engine, scheduler, or
human UI.

**Trust boundary:** the host application and database administrators are trusted.
Actor IDs are caller-supplied attribution. Workflow role checks enforce
application policy. Replay detects inconsistency and reconstructs supported
state; it does not establish tamper-evidence, non-repudiation, identity, or
external freshness. There is no signing or key material.

## Architecture

### Isolation: schema-per-project

One PostgreSQL database, one schema per project. The `Regista` handle owns one
logical project namespace. The connection pool is shared; `SET LOCAL search_path`
scopes each transaction. `synchronous_commit = on` is set on every connection.

### Core data model

- **Events** (`events`): immutable append-only log. Gap-free `event_seq` per
  work item, allocated under a canonical row lock (or advisory lock for
  non-work-item entities). Global `UNIQUE(event_id)`.
- **Projection** (`work_items_current`): denormalized, transactionally-consistent
  with events. Fully derivable from the log via replay.
- **Claims** (`claims`): durable leases with TTL, attempt tracking, and
  auto-steal on expiry.
- **Workflow registry** (`workflow_registry`): append-only, versioned workflow
  definitions. Work items pin the version they were created against.
- **Actor roles** (`actor_roles`): actor → allowed-role mapping for
  `strict_roles` enforcement.
- **Project catalog** (`public.projects`): cross-project registry of schemas.

### Key invariants

- Events are authoritative. `work_items_current` is a projection, never edited
  directly.
- Every mutation acquires `SELECT FOR UPDATE` on the work item's row.
- Event append and projection update commit in the same transaction.
- Retries with the same `event_id` are idempotent; conflicting reuse refuses.
- Lease-protected mutations accept `expected_attempt_number` and refuse a stale
  attempt with `CLAIM_LOST`.
- No cryptographic verification: replay is a consistency/rebuildability check.

## Source Layout

```
src/regista/
  __init__.py           # Public API: Regista class
  _connection.py        # Connection pool, schema-per-project, search_path
  _migrations.py        # Migration runner against the fresh baseline
  _errors.py            # ErrorCode enum + RegistaError
  _types.py             # Frozen domain dataclasses
  _contract.py          # Single-source-of-truth validation/decision functions
  _jcs.py               # Deterministic canonical JSON (content hashes, no signing)
  _events.py            # Event append, gap-free seq allocation, idempotency
  _event_store.py       # Shared creation-idempotency check
  _work_items.py        # Create + structured query
  _claims.py            # Claim lifecycle
  _links.py             # Typed directed links
  _transition.py        # Transition validation + commit
  _replay.py            # Rebuild projection, honest drift reporting
  _integrity.py         # Startup migration + workflow compatibility checks
  _observability.py     # Structured logging + Prometheus metrics
  _datetime_utils.py    # Shared datetime comparison for replay
  _actor_roles.py       # Actor → allowed-role registration and enforcement
  _projects.py          # Project catalog (public.projects)
  _version_info.py      # Version surface (library/schema/canonical workflow)
  _doctor.py            # Reachability/schema health check
  _testing.py           # Test-only helpers
  _ops.py               # Facades: WorkflowOps, WorkItemOps, EventOps, ClaimOps, LinkOps
  _api_base.py          # Shared mixin type stub
  _api_workflow.py      # Workflow/work-item/event/query/transition API mixin
  _api_claim.py         # Claim/link API mixin
  _events_api.py        # Event API helpers
  _claims_api.py        # Claim API helpers
  _links_api.py         # Link API helpers
  _work_items_api.py    # Work-item API helpers
  _workflow_api.py      # Workflow registration API helpers
  _cli.py               # Admin CLI entry point
  _workflow.py          # YAML parse, JSON Schema validate, semantic checks
  _workflow_schema.json # JSON Schema for workflow YAML
  workflows/
    canonical.workflow.yaml  # Shipped lifecycle example workflow
  _vendor/
    rfc8785.py          # Vendored RFC 8785 canonicalizer
  py.typed
migrations/
  001_initial.sql       # The single 0.8.0 baseline (schema version 1)
examples/
  worker_reviewer.py    # Worker/reviewer handoff, claim race, stale-attempt refusal
  document_processing.py# Non-agent document pipeline with human correction
```

## Testing

```bash
# Start Postgres
docker compose -f docker-compose.test.yml up -d

# Run tests (kernel suite; no in-memory backend)
.venv/bin/python -m pytest tests/ -v

# Run including slow property-based tests
.venv/bin/python -m pytest tests/ -v -m slow

# Lint
.venv/bin/ruff check src/ tests/

# Type-check (strict; burndown list in pyproject.toml [tool.mypy])
.venv/bin/mypy
```

Test DSN: `postgresql://regista_test:regista_test@localhost:5432/regista_test`.
Test workflows: `tests/` fixtures and the `examples/*.yaml` files.

The in-memory backend was removed; tests use disposable PostgreSQL schemas.

## Public API

`Regista` is the sole entry point — no Postgres internals leak across the
boundary.

```python
from regista import Regista

# Create a new project (schema + migrations on an empty destination)
sub = Regista.create_project(dsn, "my_project")

# Connect to an existing project
sub = Regista(dsn, "my_project")

# Workflows
sub.register_workflow(yaml_content)          # or sub.workflows.register(...)
sub.register_workflow_file(path)
sub.get_workflow(name, version)

# Work items
sub.create_work_item(workflow, type, actor_id, actor_kind="agent", *,
                     custom_fields=None, not_before=None, event_id=None)
sub.create_work_items_batch(items, actor_id, actor_kind="agent")
sub.query_work_items(*, workflow_name=None, workflow_version=None,
                     work_item_types=None, current_states=None, claimed_by=None,
                     claimable_now=None, needs_review=None, has_link_type=None,
                     custom_field_filters=None, cursor=None, page_size=100)
sub.get_work_item(work_item_id)
sub.update_not_before(work_item_id, not_before, actor_id, ...)

# Transitions and events
sub.transition(work_item_id, transition_name, actor_id, actor_kind="agent",
               actor_metadata=None, *, payload=None, custom_fields=None,
               event_id=None, expected_event_seq=None, expected_attempt_number=None)
sub.append_event(work_item_id, actor_id, *, transition=None, payload=None,
                 event_id=None, expected_event_seq=None)
sub.read_events(*, work_item_id=None, actor_id=None, start=None, end=None,
                transition=None, limit=100, before_seq=None)
sub.read_events_since(work_item_id, after_seq, *, limit=100)

# Claims
sub.acquire_claim(work_item_id, actor_id, ttl_seconds=300, *,
                  event_id=None, actor_kind="agent", actor_metadata=None)
sub.heartbeat_claim(work_item_id, actor_id, ttl_seconds=300, *,
                    expected_attempt_number=None, coalesce_threshold=None)
sub.release_claim(work_item_id, actor_id, *, event_id=None)
sub.sweep_expired_claims()

# Links
sub.create_link(from_id, to_id, link_type, actor_id, ...)
sub.remove_link(from_id, to_id, link_type, actor_id, ...)
sub.list_links(work_item_id)

# Replay / version / lifecycle
sub.replay(*, work_item_id=None)              # -> ReplayReport
sub.versions()                                # -> VersionInfo
sub.close()

# Facade API (Plan 007) — domain-scoped sub-objects
sub.workflows.register(yaml_content)
sub.work_items.create(...) / .query(...) / .get(...)
sub.events.append(...) / .read(...)
sub.claims.acquire(...) / .heartbeat(...) / .release(...) / .sweep_expired()
sub.links.create(...) / .remove(...) / .list(...)

# Standalone utilities (no database required)
validate_yaml(yaml_string_or_path)            # -> ValidationResult
parse_and_validate(yaml_string)
parse_file(path)
canonical_workflow_yaml()
versions()
```

**API constraints:**

- `append_event` rejects transitions that match a workflow-defined transition
  name — use `transition()` for state changes. Reserved intrinsic transitions
  (`created`, `claim_*`, `link_*`, `escalated`, `not_before_set`, `checkpoint`,
  `hook_dead_lettered`) can never be appended manually.
- `heartbeat_claim` accepts optional `expected_attempt_number` to detect stale
  sessions after claim theft.
- Claim mutations (acquire, release, sweep) emit events for the audit trail;
  heartbeats coalesce within `max(60s, ttl/2)`.
- Escalation fires inside `acquire_claim` when `attempt_number >=
  attempt_threshold`: sets `needs_review`, emits `escalated`, idempotent.
- `strict_roles=True` requires actors to have registered roles before
  transitioning; a `role_source` other than `config`/`env` is rejected.
- Transition field `privileged: true` requires `actor_kind="system"`.
- `expected_attempt_number` on `transition` fences against a stolen/expired
  lease (`CLAIM_LOST`).
- `create_project` refuses old/unknown schemas before writing; there is no
  in-place upgrade.
- Workflow fields `validator`, `hooks`, and `validator_params` are accepted by
  the schema but **not executed** in 0.8.0 (the validator/hook subsystems were
  removed).

## Admin CLI

`regista` console script (`src/regista/_cli.py`). Commands:

`workflow validate`, `work-item show/list/create/transition`, `events
show/tail`, `replay`, `schema init/status`, `actor-roles list`, `version --json`,
`doctor --json`.

Connection comes from `--dsn`/`--project` or `REGISTA_DSN`/`REGISTA_PROJECT`.
`workflow validate` and `version` need no database.

## Key Design Decisions

1. **Schema-per-project** not DB-per-project: one pool, one backup target,
   engine-enforced isolation via `GRANT ON SCHEMA`.
2. **Library, no server.** Runs in-process; exposes a
   `prometheus_client.CollectorRegistry` for the host to mount. No background
   thread and no HTTP sidecar in 0.8.0 — sweep and replay are explicit calls.
3. **Hybrid persistence.** Events authoritative; projection updated in the same
   transaction. Not pure event-sourcing (no per-read replay cost).
4. **No signing.** Actor IDs are attribution, not authentication. Canonical JSON
   remains for idempotency/content hashing only.
5. **Fresh baseline.** One consolidated `migrations/001_initial.sql`; old schemas
   are refused without mutation.

## Known Constraints

- **Schema-per-project requires session-scoped `search_path`.** Incompatible
  with transaction-mode connection poolers (e.g. PgBouncer transaction mode);
  use session mode or connect directly.
- **`events` is flat.** A global `UNIQUE(event_id)` index ensures identity;
  per-work-item `event_seq` is gap-free. No partitioning.
- **A lease is not exactly-once external effect.** Lease fencing stops a stale
  worker from committing protected changes to regista; it does not stop that
  process from making external requests. The application owns downstream
  idempotency.
- **Trusted-host boundary.** A database administrator can read/write the schema
  directly. Replay does not defend against that.

## Agent Workflow

This project tracks work outside the code. New agents should orient to these
conventions before making changes.

### Work tracking (issues)

Work items for this project live in **regista** — the single source of truth.
The agent-notes store is a read projection of it. **Do not create physical
breadcrumb files** (`breadcrumbs/`, `OPEN_BREADCRUMBS.txt`, `*.breadcrumb.md`);
the file-based store is retired. Regista dogfoods its own convergence: it tracks
its work in regista.

**Agent face — the `agent-notes` CLI (and `/file-breadcrumb` etc.).** Run from
the repo root so `--path .` resolves this project; the CLI routes to this
project's regista schema automatically.

```bash
# File an issue
agent-notes breadcrumb file --path . --title "<short title>" \
    --type <kind> [--severity low|medium|high|critical] [--body "<details>"]

# Find / show / update
agent-notes breadcrumb find  --path . [--status open] [--type bug] [--text "<q>"]
agent-notes breadcrumb get   --path . <WI-id>
agent-notes breadcrumb update --path . <WI-id> [--status <state>] [--title ...] [--body ...]
```

**Lifecycle (canonical):**
`open → in_progress → (blocked | deferred) → in_review → in_human_review → done`.
`done` is reachable only through the two-stage review gate (a cross-lineage
adversarial-review pass, then accept), except a pre-work `close_from_open`
dismissal (won't-fix / duplicate). "Who's working this" is a regista **claim** (a
separate liveness axis), not a lifecycle state.

Open the backlog before starting work — `agent-notes breadcrumb find --path .
--status open` is the canonical "what's known to be wrong" list. When you notice
an issue you're not fixing, file it; when you fix one, transition it. The `/end`
command does both via the CLI.

### Worklog (`.regista/worklog.md`)

Reverse-chronological session log. Each entry: focus, context, what was delivered
(with file references), breadcrumbs resolved, test/lint results. Read the most
recent entry on session start; prepend a new entry on session end.

### Reflections (`.regista/reflections/`)

Per-session subjective notes. Read the latest before starting; write one via the
`/reflect` skill.

### Session commands

Regista-specific wrappers in `.regista/commands/`:

- `/start` — orient to current state (worklog tail, open breadcrumbs, git status)
- `/end` — run tests, reconcile breadcrumbs, update worklog, write reflection, commit
- `/reflection` — write a reflection only

System-wide skills (`/reflect`, `/end`) provide portable equivalents; the
regista-specific versions add test runs and worklog updates.

## Status

The 0.8.0 reduced kernel is implemented: workflows, work items, claims with
fencing, events + projection, replay, idempotency, custom fields, typed links,
structured queries, schema-per-project isolation, and the admin CLI. Test suite:
`tests/` (workflow, work items, claims, transitions, links, events, replay, CLI,
doctor, schema baseline, examples). Production readiness: pip-installable
migration packaging, `mypy --strict` ratchet (see `[tool.mypy]` in
`pyproject.toml`), structured errors, and a bounded maintenance policy (release
regressions and serious security/data-loss defects only; no feature roadmap).