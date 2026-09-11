# Regista examples

Two runnable examples that exercise the regista coordination kernel through its
public API. Neither needs signing keys, suite configuration, or private modules.

## Prerequisites

A disposable PostgreSQL database. From the repository root:

```bash
docker compose -f docker-compose.test.yml up -d
```

The scripts default to the test DSN
`postgresql://regista_test:regista_test@localhost:5432/regista_test`. Override it
with the first argument or `REGISTA_EXAMPLE_DSN`. If you omit the project name,
each run creates a uniquely named disposable project and leaves it in place.

## Worker/reviewer handoff

```bash
PYTHONPATH=src .venv/bin/python examples/worker_reviewer.py
```

A discovery step files a remediation item linked to two related items. Two
workers race for it; the loser gets `CLAIM_CONTESTED`. The winner records a
result, hands the item to a reviewer, and is sent back once with
`request_changes`. It re-acquires a new attempt, a stale `expected_attempt_number`
is refused with `CLAIM_LOST`, and a fresh review reaches `done`.

## Document processing

```bash
PYTHONPATH=src .venv/bin/python examples/document_processing.py
```

An ingestion step files a document with a `source_ref` and a scheduled follow-up
item, linking them. A processing worker records extracted fields, a person
corrects them through a transition, and the document is committed. The script
also shows claimable, owned, and review-ready queries plus a `not_before` gate.

## Leases are not exactly-once external effects

A regista claim is a durable lease: it guarantees that one worker owns an
attempt and that stale attempts are refused. It does **not** make a downstream
external effect happen exactly once. If a worker performs the external write and
then crashes before recording the result, a retry can run the write again.

The application owns duplicate protection for external systems. Generate a
stable operation key before the effect and have the downstream system de-dupe on
it. `worker_reviewer.py` models this with a small `DownstreamLedger`; regista
also makes the event append idempotent when you retry with the same `event_id`.

## Cleanup

The examples leave their disposable schemas behind. Drop them with:

```bash
psql postgresql://regista_test:regista_test@localhost:5432/regista_test \
  -c 'DROP SCHEMA IF EXISTS ex_worker_xxx CASCADE'
```

The test suite drops its own schemas after each run.