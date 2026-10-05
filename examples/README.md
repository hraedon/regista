# Runnable coordination examples

Install this candidate's wheel and use disposable PostgreSQL 15. Each command
needs its own empty database (or an already initialized baseline with no
conflicting example workflows/items). No configuration files or keys are needed.

```bash
regista --help
python examples/example_handoff.py "$REGISTA_TEST_DSN"
python examples/example_documents.py "$REGISTA_TEST_DSN"
```

The handoff scenario races two worker processes, records results, requests
changes, terminates a worker, waits for expiry, takes over, rejects stale attempts
and completes fresh review. The document scenario loads its own workflow and
runs human correction through `python -m regista.cli` from the installed package.
Fields merge shallowly; `unset_fields` removes a field. Leases persist through
transitions until explicit release. Stable operation keys deduplicate Regista
writes; deduplication of external effects remains the downstream application's job.

[Original F0a fit report](../plans/032-f0-inventory/F0a-report.md).
