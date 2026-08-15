# regista

Coordination and durable state for agent pipelines over Postgres.

[![CI](https://github.com/hraedon/regista/actions/workflows/ci.yml/badge.svg)](https://github.com/hraedon/regista/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)]()

Regista is a Python library that provides durable claims, event-sourced state, validated state transitions, and typed links for multi-role agent pipelines. Each project deploys regista as its own isolated instance using schema-per-project isolation within a single Postgres database.

## Features

- **Event-sourced state** — immutable append-only event log; projection rebuilt by replay
- **Event hash chain** — each event's `prev_event_hash` binds it to its predecessor (SHA-256 of prev envelope + signature)
- **Durable claims** — lease-based work claiming with TTL, auto-steal, and attempt tracking
- **Validated transitions** — workflow-defined state machines with role gating and sync validators
- **Typed links** — directed relationships between work items with link types declared in workflow YAML
- **Hook queue** — async event dispatch with dead-letter, retry, and out-of-process claim/complete/fail lifecycle
- **Custom fields** — typed fields with JSON Schema validation, enum support, and JSONB containment queries
- **Recurring work items** — interval and RRULE schedules with catch-up policies
- **Workflow composition** — `extends:` inheritance with keyed list merge and `__append`/`__remove` modifiers
- **Facade API** — domain-scoped sub-objects (`sub.workflows`, `sub.work_items`, `sub.claims`, etc.)
- **Maintenance thread** — background sweep, recurrence firing, hook lease cleanup, and witness delivery
- **Trust hardening** — `strict_roles` enforcement, env-var key injection, vendored RFC 8785
- **Delegation chain** — `on_behalf_of` field for agent-to-principal binding (Plan 010)
- **Pluggable signing** — HMAC-SHA256 (default) and Ed25519 via `SigningScheme` protocol (Plan 011)
- **RFC 3161 timestamping** — Merkle tree batching against external TSA for event integrity (Plan 012)
- **Witness co-signing** — external witness registration, receipt creation, and HTTP delivery (Plan 013)
- **Webhooks** — push-model event delivery with auto-pause on failure
- **Event archival** — `archive_events` moves old events to archive table, preserving hash chain integrity
- **Batch operations** — `create_work_items_batch` for multi-create in a single transaction
- **HTTP sidecar** — optional FastAPI pass-through for non-Python consumers with bearer-token auth
- **Admin CLI** — `regista` command for workflow validation, work-item CRUD, event archival, witness management, and more
- **Prometheus metrics** — built-in counters for claims, transitions, events, hooks, escalations, witnesses, timestamping
- **In-memory backend** — full conformance backend for testing without Postgres

## Quick Start

```bash
# Install
pip install -e .

# With HTTP sidecar support
pip install -e ".[sidecar]"

# With Ed25519 signing support
pip install -e ".[ed25519]"

# With RFC 3161 timestamping support
pip install -e ".[timestamping]"

# Install everything
pip install -e ".[sidecar,ed25519,timestamping]"

# Start test Postgres
docker compose -f docker-compose.test.yml up -d

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/
```

## Usage

```python
from regista import Regista

# Initialize a project (one-time)
sub = Regista.create_project(
    dsn="postgresql://user:pass@host:5432/mydb",
    project="factory",
    hmac_key_path="/secrets/regista-keys.json",
)

# In the 0.6.0 clean epoch, open the project explicitly with an externally
# prepared v6/Ed25519 genesis envelope. Legacy append APIs are refused until
# the v6 ordinary-event writer is enabled.
genesis = sub.write_genesis(genesis_envelope, gate_passed=True)
assert sub.read_genesis().event_hash == genesis.event_hash

# InMemoryRegista remains a legacy-only test backend and fails closed in the
# clean epoch until it gains an equivalent v6 genesis implementation.

# The legacy operation examples below document the historical API; legacy
# writers are refused on the clean baseline before and after genesis.
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
regista_version: "0.1.0"

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

## Key Format

```json
{
  "keys": [
    {
      "key_id": "key-001",
      "secret": "base64-encoded-secret",
      "status": "active",
      "scheme": "hmac-sha256"
    },
    {
      "key_id": "key-002",
      "secret": "base64-encoded-ed25519-seed",
      "public_key": "base64-encoded-ed25519-public-key",
      "status": "active",
      "scheme": "ed25519",
      "encoding": "base64"
    }
  ]
}
```

Key statuses: `active`, `deprecated` (accepted with warning), `revoked` (rejected).
Signing schemes: `hmac-sha256` (default), `ed25519` (requires `pip install regista[ed25519]`).

## HTTP Sidecar

The optional sidecar exposes the full Regista API over HTTP for non-Python consumers:

```bash
pip install ".[sidecar]"

export REGISTA_DSN="postgresql://user:pass@host:5432/mydb"
export REGISTA_PROJECT="factory"
export REGISTA_HMAC_KEY_PATH="/secrets/keys.json"
export REGISTA_TOKENS_PATH="/secrets/tokens.yaml"

python -m regista.sidecar
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
regista workflow validate my-workflow.yaml

# Compose workflow with extends:
regista workflow compose my-workflow.yaml --json

# Inspect work items
regista work-item show <uuid>
regista work-item list --workflow my_workflow --claimable-now

# Create and transition work items
regista work-item create --workflow my_workflow --type feature --actor agent-1 --confirm
regista work-item transition <uuid> --transition start --actor agent-1 --confirm

# View events
regista events show <uuid>
regista events tail --actor agent-1 --since "2026-05-01T00:00:00Z"
regista events archive --before "2026-01-01T00:00:00Z" --dry-run

# Replay drift check
regista replay

# Manage recurrence rules
regista recurrence list
regista recurrence due
regista recurrence fire <rule-uuid>

# Schema management
regista schema init
regista schema status

# Dead-lettered hooks
regista hooks dead-letter list
regista hooks dead-letter requeue <id>

# Actor roles
regista actor-roles list --actor agent-1

# Witnesses
regista witness list
regista witness deliver
regista witness receipts --event-id <uuid>

# Webhooks
regista webhook register --url https://example.com/hook --transitions start,complete
regista webhook list

# Timestamping
regista timestamp status
regista timestamp trigger
```

## Architecture

- **Event-sourced**: events are the authoritative log; `work_items_current` is a transactionally-consistent projection
- **Hash-chained events**: each event's `prev_event_hash` creates a tamper-evident chain within each work-item
- **Schema-per-project**: one Postgres database, one schema per project, engine-enforced isolation
- **Library mode**: runs in-process, no HTTP server required; optional `start_maintenance()` background thread for sweep, recurrence, and witness delivery
- **Pluggable signing**: HMAC-SHA256 (default) or Ed25519 via `SigningScheme` protocol; library is sole signer
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

# Type-check (strict; burndown list in pyproject.toml [tool.mypy])
mypy
```

Test DSN: `postgresql://regista_test:regista_test@localhost:5432/regista_test`

## Documentation

- **`spec.md`** — authoritative specification
- **`spec.yaml`** — machine-readable spec sidecar
- **`AGENTS.md`** — developer guide, source layout, conventions, and project status
- **`CHANGELOG.md`** — version history
- **`deploy/sidecar/README.md`** — sidecar deployment guide

## Status

All features through Plan 022 implemented. FR-01 through FR-29 in tree. See `AGENTS.md` for detailed status.

## License

MIT. See [LICENSE](LICENSE).
