# Plan 002 — Minimal Admin CLI for Regista

**Status:** Draft
**Owner:** operator
**Prereq for:** archival CLI (separate plan)

## 1. Motivation & Scope

Regista currently has zero CLI. Operational debugging requires connecting to Postgres directly and reading raw tables, bypassing the library's signing, replay, and validation primitives. That is both error-prone (the operator can drift the projection — forbidden by `spec.md` §18) and wasteful (replay, workflow validation, and structured queries already exist as Python API).

This plan delivers a small, in-process CLI that wraps the existing `Regista` class (`src/regista/__init__.py:84`) and the standalone `validate_yaml` helper (`src/regista/_workflow.py`, re-exported at `__init__.py:79`) for operator use. The CLI is:

- **Not a sidecar.** Runs in-process, loads the library, opens the normal connection pool, signs through `KeySet`.
- **Operator-only.** Local execution against a project the operator already has DB credentials and HMAC key access for.
- **Read-heavy.** Mutating commands are limited to schema bootstrap (which the library already does) and dead-letter requeue.

Out of scope: anything in §8.

## 2. CLI Framework Choice

**Recommendation: argparse (stdlib).**

Rationale:
- `pyproject.toml:10-18` lists seven runtime deps; none is a CLI framework. Adding Click or Typer expands the dependency surface for a small command set.
- The command tree is shallow (≤ 3 levels: `regista workflow validate <file>`) and the argument shapes are simple. argparse subparsers handle this idiomatically.
- Regista is a library first; an embedded CLI that vendors no third-party CLI deps stays consistent with the "library, not daemon" stance (`AGENTS.md` §Key Design Decisions, point 2).

Click would be the next choice if the surface grows beyond ~10 commands or if rich `--help` formatting becomes a priority. Defer until then.

## 3. Connection, Config, and Signing

The CLI MUST instantiate `Regista(dsn, project, hmac_key_path=...)` (`__init__.py:92`) — not bypass it. This is non-negotiable: `spec.md` §19.2 and FR-15 state the library is the **sole sanctioned signer** and AC-33 forbids pre-signed event submission. The CLI therefore inherits signing for free; it never touches `KeySet` directly or constructs canonical envelopes.

Config resolution order (first wins):

1. **CLI flags:** `--dsn`, `--project`, `--hmac-key-path`
2. **Environment variables:** `REGISTA_DSN`, `REGISTA_PROJECT`, `REGISTA_HMAC_KEY_PATH`
3. **No config file in v1.** Defer; env + flags cover the homelab single-operator case and keep secret material off disk in a known location.

The DSN MUST point at a Postgres reachable directly or via PgBouncer **session mode** (`AGENTS.md` "Known constraints" — transaction-mode pooling is incompatible with `SET LOCAL search_path`).

For commands that only need workflow validation (`workflow validate`), the CLI MUST NOT require DSN or key path — `validate_yaml()` is a pure function (`__init__.py:79`).

## 4. Command Surface

Format: `regista <group> <verb> [args]`. R = read-only, M = mutating.

| Command | Mode | Maps to |
|---|---|---|
| `regista workflow validate <yaml-file>` | R (no DB) | `validate_yaml()` (`__init__.py:79`) |
| `regista work-item show <id>` | R | `Regista.get_work_item()` (`__init__.py:871`) |
| `regista work-item list [--workflow N] [--state S] [--type T] [--needs-review] [--claimable-now] [--page-size N] [--cursor U]` | R | `Regista.query_work_items()` (`__init__.py:817`) |
| `regista events show <work-item-id> [--limit N] [--before-seq N]` | R | `Regista.read_events(work_item_id=...)` (`__init__.py:738`) |
| `regista events tail [--actor A] [--transition T] [--since ISO] [--until ISO] [--limit N]` | R | `Regista.read_events()` cross-item form |
| `regista replay [--continue-on-revoked]` | R (drift check only — replay writes to a *separate* table per `_replay.drop_old_replay_tables` and does not mutate `work_items_current`) | `Regista.replay()` (`__init__.py:1143`) |
| `regista schema init` | M (bootstrap) | `Regista.create_project()` (`__init__.py:148`) |
| `regista schema status` | R | `Regista.regista_version` + integrity check via constructor (`check_integrity`, `__init__.py:142`) |
| `regista hooks dead-letter list` | R | `Regista.list_dead_lettered_hooks()` (`__init__.py:1207`) |
| `regista hooks dead-letter requeue <id>` | M | `Regista.requeue_dead_lettered_hook()` (`__init__.py:1186`) |
| `regista actor-roles list [--actor A]` | R | `Regista.list_actor_roles()` (`__init__.py:1366`) |

Notes:
- `replay` is classified read-only on the live projection. It does write to a replay-scratch table, but `work_items_current` is untouched (per `spec.md` §18 and the docstring on `_replay`).
- `hooks dead-letter requeue` and `schema init` are the only mutating verbs. Both go through existing signed paths.
- No `transition`, `claim`, `link`, `create-work-item`, or `update-not-before` — those are agent-driven operations, not operator debugging. Adding them invites footguns where the operator becomes a participating actor in the event log under an `actor_id` that has no role mapping.

Every command exits non-zero on `RegistaError`, printing `error_code` and `message` to stderr.

## 5. Output Format

- **Default:** human-readable, one-record-per-block for `show`, table for `list`. Columns chosen for terseness (UUID first 8 chars + ellipsis where width-constrained; full UUIDs accessible via `--json`).
- **`--json` flag:** emits the dataclass dicts (frozen dataclasses already exist in `_types.py`) via a small `asdict`-with-uuid/datetime-string normalizer. UUIDs as strings, timestamps as ISO 8601 Z. Stable key order. No trailing newlines beyond one per record so `jq -c` works.
- `--no-color` honored, but color is off by default (no `rich`/`colorama` dep).
- Exit codes: `0` ok, `1` operational error (DB, key, validation), `2` argument error.

## 6. Test Approach

- **Unit tests** for argument parsing and output formatting (no DB). Lives in `tests/test_cli_args.py`. Asserts subparser tree, env var precedence, `--json` schema for each command's output shape (golden snapshots).
- **Integration tests** against the existing test Postgres (`docker-compose.test.yml`, DSN per `AGENTS.md` §Testing). One test per command, using `Regista.create_project()` to seed and then shelling out to `python -m regista <cmd>` via `subprocess.run`. Lives in `tests/test_cli_integration.py`.
- **Workflow-validate** test reuses `tests/test_workflow.yaml` (referenced in `AGENTS.md`).
- **Replay drift** test: seed events, hand-corrupt `work_items_current` via direct SQL (deliberately violating §18 to exercise the detector), run `regista replay --json`, assert `replayed_drift > 0`.
- No new test framework deps; pytest + subprocess only.

Entry point wiring in `pyproject.toml`:

```toml
[project.scripts]
regista = "regista._cli:main"
```

Module lives at `src/regista/_cli.py` (underscore-prefixed: implementation, not public re-export). Public surface stays the `Regista` class.

## 7. Open Questions & Risks

- **Remote execution:** out of scope for v1. CLI assumes local invocation with operator-readable DSN and key path. A remote sidecar that re-uses this code path is a future plan; the `Regista` instance is process-local and there is no auth model beyond Postgres role + key file ownership.
- **Concurrent mutating operators:** `schema init` is idempotent at the Postgres level (CREATE SCHEMA IF NOT EXISTS via `_connection.create_schema`), and migrations are gated by a migration-version table per `_migrations.run_migrations`. `hooks dead-letter requeue` is event-driven and acquires the standard row lock; two operators requeueing the same id will produce one success and one `HOOK_NOT_FOUND`. Acceptable.
- **Schema-init from CLI runs migrations under whatever role the DSN gives.** Document that the DSN role needs `CREATE` on the database. No new privilege model.
- **Key rotation:** the CLI uses the same `KeySet` hot-reload as the library; no extra surface.
- **`regista` shell name collision:** unlikely on operator hosts, but worth checking before wiring the entry point.

## 8. Out of Scope

- HTTP, gRPC, or any network listener
- Archival commands (separate plan)
- Work-item creation, transition, claim acquire/release/heartbeat, link create/remove, `update_not_before`, validator/hook handler registration — these are agent-actor operations, not operator debugging
- Interactive TUI, pagers, color themes
- Cross-project queries (forbidden by `spec.md` BR-04)
- Direct event append (`append_event`) — would put the operator into the audit trail with an unregistered role
- Config file format
- Shell completion (defer; argparse generates it via `argcomplete` later if wanted)
