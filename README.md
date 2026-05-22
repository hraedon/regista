# substrate

Coordination and durable state for agent pipelines over Postgres.

[![CI](https://github.com/hraedon/substrate/actions/workflows/ci.yml/badge.svg)](https://github.com/hraedon/substrate/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-721%20passing-brightgreen)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()

Substrate is a Python library that provides durable claims, event-sourced state, validated state transitions, and typed links for multi-role agent pipelines. Each project deploys substrate as its own isolated instance using schema-per-project isolation within a single Postgres database.

## Features

- **Event-sourced state** — immutable append-only event log; projection rebuilt by replay
- **Durable claims** — lease-based work claiming with TTL, auto-steal, and attempt tracking
- **Validated transitions** — workflow-defined state machines with role gating and sync validators
- **Typed links** — directed relationships between work items with link types declared in workflow YAML
- **Hook queue** — async event dispatch with dead-letter, retry, and out-of-process claim/complete/fail lifecycle
- **Custom fields** — typed fields with JSON Schema validation, enum support, and JSONB containment queries
- **Recurring work items** — interval and RRULE schedules with catch-up policies
- **Workflow composition** — `extends:` inheritance with keyed list merge and `__append`/`__remove` modifiers
- **Facade API** — domain-scoped sub-objects (`sub.workflows`, `sub.work_items`, `sub.claims`, etc.)
- **Maintenance thread** — background sweep, recurrence firing, and hook lease cleanup
- **Trust hardening** — `strict_roles` enforcement, env-var key injection, vendored RFC 8785
- **HMAC-SHA256 signing** — RFC 8785 canonicalization; library is sole signer
- **HTTP sidecar** — optional FastAPI pass-through for non-Python consumers with bearer-token auth
- **Admin CLI** — `substrate` command for workflow validation, work-item inspection, replay, and recurrence management
- **Prometheus metrics** — built-in counters for claims, transitions, events, hooks, escalations
- **In-memory backend** — full conformance backend for testing without Postgres

## Quick Start

```bash
# Install
pip install -e .

# With HTTP sidecar support
pip install -e ".[sidecar]"

# Start test Postgres
docker compose -f docker-compose.test.yml up -d

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/
```

## Usage

```python
from substrate import Substrate

# Initialize a project (one-time)
sub = Substrate.create_project(
    dsn="postgresql://user:pass@host:5432/mydb",
    project="factory",
    hmac_key_path="/secrets/substrate-keys.json",
)

# Register a workflow
sub.register_workflow_file("workflows/spec-pipeline.yaml")

# Create work
wi, event = sub.create_work_item(
    workflow_name="spec_pipeline",
    work_item_type="feature",
    actor_id="agent-1",
    actor_metadata={"role": "agent", "model": "gpt-4"},
    custom_fields={"title": "Add authentication"},
)

# Claim and transition
claim = sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

# Query available work
page = sub.query_work_items(
    workflow_name="spec_pipeline",
    claimable_now=True,
    current_states=["new"],
)

# Replay for integrity check
report = sub.replay()
assert report.replayed_drift == 0

# Schedule recurring work
rule = sub.register_recurrence_rule(
    workflow_name="spec_pipeline",
    workflow_version=1,
    work_item_type="feature",
    template={"custom_fields": {"title": "Weekly sync"}},
    schedule_kind="interval",
    schedule_expr="P7D",
)

sub.close()
```

## Workflow Definitions

Workflows are YAML files validated against a JSON Schema:

```yaml
name: my_workflow
version: 1
substrate_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: in_progress
  - name: review
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: in_progress
    allowed_roles: [agent]
    hooks: [notify_reviewer]
  - name: submit_review
    from: in_progress
    to: review
    allowed_roles: [agent]
  - name: approve
    from: review
    to: done
    allowed_roles: [reviewer]

roles:
  - name: agent
  - name: reviewer

work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true
        ui_visible: true
      - name: priority
        type: enum
        enum_values: [low, medium, high]
      - name: metadata
        type: json

link_types:
  - name: depends_on
    source_type: feature
    target_type: feature

hook_defaults:
  max_retries: 3

attempt_threshold: 3
```

### Workflow Composition

Workflows can extend other workflows using `extends:`:

```yaml
name: extended_pipeline
extends: base_pipeline.yaml
transitions:
  - name: escalate
    from: review
    to: escalated
    __append: true
```

## HMAC Key Format

```json
{
  "keys": [
    {
      "key_id": "key-001",
      "secret": "base64-encoded-secret",
      "status": "active"
    }
  ]
}
```

Key statuses: `active`, `deprecated` (accepted with warning), `revoked` (rejected).

## HTTP Sidecar

The optional sidecar exposes the full Substrate API over HTTP for non-Python consumers:

```bash
pip install ".[sidecar]"

export SUBSTRATE_DSN="postgresql://user:pass@host:5432/mydb"
export SUBSTRATE_PROJECT="factory"
export SUBSTRATE_HMAC_KEY_PATH="/secrets/keys.json"
export SUBSTRATE_TOKENS_PATH="/secrets/tokens.yaml"

python -m substrate.sidecar
```

Token file (`tokens.yaml`):

```yaml
tokens:
  - token_sha256: "<sha256-hex-of-raw-token>"
    actor_id: "agent-1"
    actor_kind: "agent"
    allowed_roles: ["agent", "reviewer"]
```

All endpoints are under `/v1/`. Requests must not include `signature` or `payload_canonical_hash` (the sidecar signs internally). OpenAPI docs available at `/docs`.

A Dockerfile is provided in `deploy/sidecar/`.

## Admin CLI

```bash
# Validate a workflow YAML (no database required)
substrate workflow validate my-workflow.yaml

# Inspect work items
substrate work-item show <uuid>
substrate work-item list --workflow my_workflow --claimable-now

# View events
substrate events show <uuid>
substrate events tail --actor agent-1 --since "2026-05-01T00:00:00Z"

# Replay drift check
substrate replay

# Manage recurrence rules
substrate recurrence list
substrate recurrence due
substrate recurrence fire <rule-uuid>

# Schema management
substrate schema init
substrate schema status

# Dead-lettered hooks
substrate hooks dead-letter list
substrate hooks dead-letter requeue <id>

# Actor roles
substrate actor-roles list --actor agent-1
```

## Architecture

- **Event-sourced**: events are the authoritative log; `work_items_current` is a transactionally-consistent projection
- **Schema-per-project**: one Postgres database, one schema per project, engine-enforced isolation
- **Library mode**: runs in-process, no HTTP server required; optional `start_maintenance()` background thread for sweep and recurrence
- **Library is sole signer**: HMAC-SHA256 over RFC 8785 canonical JSON, computed internally
- **Flat events table**: global `UNIQUE(event_id)` index; partitioning removed in RFC-001
- **Single-source-of-truth contract**: shared validation/decision functions in `_contract.py` used by both Postgres and in-memory backends
- **Property-based testing**: hypothesis-driven conformance tests verify both backends behave identically

## Testing

```bash
# Start Postgres
docker compose -f docker-compose.test.yml up -d

# Run core tests
pytest tests/ -v

# Run including property-based tests (slow)
pytest tests/ -v -m slow

# Run sidecar tests
pytest tests/sidecar/ -v

# Lint
ruff check src/ tests/
```

Test DSN: `postgresql://substrate_test:substrate_test@localhost:5432/substrate_test`

## Documentation

- **`spec.md`** — authoritative specification
- **`spec.yaml`** — machine-readable spec sidecar
- **`AGENTS.md`** — developer guide, source layout, conventions, and project status
- **`CHANGELOG.md`** — version history
- **`deploy/sidecar/README.md`** — sidecar deployment guide

## Status

All features through Plan 009 implemented. 721 tests passing (core, sidecar, property-based, and plan-specific). FR-01 through FR-29 in tree. 198 breadcrumbs resolved. See `AGENTS.md` for detailed status.

## License

MIT. See [LICENSE](LICENSE).
