# 0.8.0 operations, trust, and preservation

Use PostgreSQL 15 (the qualified version) with Python 3.11–3.14. Explicitly pass
a DSN and one schema name to `Kernel.connect`; the CLI takes `--dsn` or
`REGISTA_DSN`, and `--schema` defaults to `public`. No private configuration,
keys, or sibling tools are required. DSNs may contain credentials: keep them out
of shared transcripts. Create service roles and grant database/schema/table
permissions yourself; Regista does not provision roles. A role initializing a
new schema needs database `CREATE` privilege; `initialize()` creates an absent
namespace transactionally. Alternatively use a pre-created owned schema;
a runtime role needs USAGE plus the required table/sequence permissions.
Use a separate database or restricted roles per trust boundary. Schema scoping
is not a substitute for PostgreSQL privilege isolation.

The trusted host binds actor attribution and role assertions to any authenticated
users it has. Regista checks the presented role against the pinned workflow;
it has no actor-role registry and authenticates nobody. Database administrators
can change records and recompute unkeyed hashes. Replay is a consistency check,
not authenticity, non-repudiation, hostile-administrator evidence, model identity,
or external freshness. Transport encryption, storage encryption, credentials,
access control, retention, and database availability are operator responsibilities.

`Kernel.connect(..., require_existing=True)` opens an existing project without
initializing it. Initialization accepts an empty destination or the supported
baseline. Old/unknown occupied schemas refuse before mutation. Unsupported kernel
versions can be opened for diagnostics, but writes and initialization refuse them.
There is no upgrade, reset, or automatic deletion. To remove a project, an operator
manually runs `DROP SCHEMA <project> CASCADE` against the intended database after
retaining its backup. This is destructive and outside Regista's API/CLI.

## Leases and handoffs

Retain the attempt returned by claim. Heartbeat and release require both holder
attribution and that attempt. Transitions on a live lease require them too;
transitions preserve leases even in terminal states. Explicit release hands work
to another participant. Expired leases authorize no writes. Takeover increments
the fencing counter, or `expire-leases [ID]` removes expired lease rows without
touching live leases. Schedule `regista --dsn ... --schema ... expire-leases`
with the operator's timer/cron policy; there is no automatic maintenance thread.
Availability/ownership and blocked queries are snapshots; claim arbitrates races.
A Regista lease never stops a process or fences external effects automatically.
Use stable downstream operation keys and target-enforced fencing where required.

## Backup and usable recovery

Back up the **whole** database, including workflow registry, events, projections,
claims, claim-attempt counters, links, and idempotency keys. The last four are
`REPLAY_DOES_NOT_COVER`: there is no event history from which to rebuild them.
Replay covers current state, custom fields/clears, final event sequence, payload
hashes, chain links, sequence density, and transition names against the pinned
workflow. `replay()` and `replay_all()` never repair tables. Whole-namespace replay
streams UUID order in batches; each item has its own repeatable-read snapshot,
so quiesce the restored namespace during verification. It includes event-only and
projection-only IDs and reports drift rather than hiding them.

With operator-supplied connection settings and a newly created **separate** restore
DB, the procedure is:

```bash
pg_dump --format=custom --no-owner --no-acl "$SOURCE_DSN" > saved.dump
pg_restore --exit-on-error --no-owner --no-acl --dbname="$RESTORE_DSN" saved.dump
regista --dsn "$RESTORE_DSN" --schema tasks check-history
regista --dsn "$RESTORE_DSN" --schema tasks health
```

Then reconnect from a fresh application process, verify expected fields, links,
claims and counters, and perform another valid create/claim/transition/release.
A verifier alone does not prove usable recovery. Check any external systems
separately; a restored database may precede an already completed external effect.

## Preserve 0.7.2 and earlier before changing anything

1. Retain an immutable copy of the old dump, its package artifact/version and a
   matching Python/dependency environment. Record artifact digests and versions.
2. Retain old keys, custody settings and trust material separately with their
   access protections. The reduced package cannot interpret their old formats.
3. Restore the dump into a scratch database and verify it with that **matching
   old environment**, including a representative read and operational check.
   Historical readers retain the defects described in the D12 assessment;
   successful reads do not regenerate or certify historical authenticity claims.
4. Only after verifying preservation, provision a fresh 0.8.0 database. There is
   no converter or in-place upgrade. Keep the old environment isolated for
   reference; do not aim the new initializer at it.

See [breaking changes](breaking-0.8.md) and
[older-release assessment](../plans/032-d12-yank-assessment.md).

## Namespace and retry contracts

`initialize()` takes no SQL-path argument: it loads the pinned packaged resource,
creates an absent schema transactionally, and accepts an existing version-1 schema
only when its complete catalog matches `baseline.manifest.json`. Every write checks
that manifest again; foreign relations, functions/types, columns, constraints,
indexes, triggers or rules refuse with `UnsupportedSchemaError`. Ownership and
grants are operator configuration, excluded from the portable manifest. A trusted
database administrator can change objects after admission; this is not hostile-admin
isolation. Unsupported-version diagnostic reads retain the A5 behavior.

Special `$user`, `pg_*` and `information_schema` names refuse with `InvalidFieldError`.
Checkout and operation verification require the effective literal namespace and its
expected path; active temporary schemas refuse to prevent relation shadowing.

Release locks the item first and waits for an already-fenced transition to commit.
It deletes only a live matching lease; an expired holder cannot remove the fence.
Takeover or an explicit sweep resolves expiry. Unlink is idempotent: an absent typed
link is a successful no-op, including concurrent or lost-response retries. Blocking
inspects only the immediate counterpart; an unsatisfied counterpart still blocks
its downstream item even when it is itself blocked.

Idempotency retries stream events through the immutable result sequence with a
server cursor in batches of 64. Memory is bounded by a batch and current fields;
time remains proportional to the history prefix. No snapshot column or schema-pin
change is needed. The unpublished baseline-1 event digest now hashes canonical JSON
`{"transition": <name-or-null>, "payload": <payload>}`; replay also checks source and
destination against the pinned workflow version. Existing pre-release stores with
the former digest are outside the qualified candidate and must be recreated.

Human CLI rendering escapes C0/C1 controls, ESC, DEL, bidi controls and embedded
line breaks. JSON mode keeps its serialization. Bad UUIDs, malformed `--field` syntax
and JSON integer/depth parser limits use exit 2, a clean refusal on stderr, and an
error/message/exit_code JSON object on stdout under `--json`.
