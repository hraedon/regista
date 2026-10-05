# 0.8.0 CLI reference

Generated from the actual parser by `scripts/generate_reference.py`.

Global options precede commands: `regista --dsn DSN --schema PROJECT --json COMMAND`.
`REGISTA_DSN` is the DSN fallback; schema defaults to `public`. Except workflow
validation, commands open an existing baseline; `init` alone permits initialization.
JSON mode emits JSON; whole-namespace `check-history` emits JSON Lines. Exit 0
means success, 1 means history drift or workflow-validation failure, and 2 means
a kernel refusal or command-line error. Human output may contain color escapes.

`--field key=value` repeats, parses a value as JSON when possible and otherwise
keeps text. Transition `--unset-field` clears keys atomically. Roles are presented
by a trusted caller; `--actor-kind` defaults to agent. There is no CLI payload flag.

`list` and `history` return one page (50 by default, at most 500) and human output
warns when full; JSON clients compare length to limit and resume explicitly.
Workflow list is the library's default first page; for registry pagination use
`Kernel.list_workflows(limit=..., after=(name, version))`. Show's outgoing links
are also the default first page; use `Kernel.links_from` to paginate all links.

The old `replay` command refuses. `check-history` is read-only and never repairs
projections. Omit its ID for the whole namespace; quiesce it for restore checking.
Leases persist until explicit release. Operators schedule `expire-leases`; service
roles and manual project `DROP SCHEMA` remain operator responsibilities.

Blocked discovery requires caller-supplied satisfied states, uses one hop and
never gates claims. See [operations](operations.md) for trust/recovery boundaries.

## `regista`

```text
usage: regista [-h] [--dsn DSN] [--schema SCHEMA] [--json] {init,health,expire-leases,workflow,create,show,list,claim,heartbeat,lease,release,transition,link,unlink,history,check-history} ...

Small administration and participation CLI over the kernel.

positional arguments:
  {init,health,expire-leases,workflow,create,show,list,claim,heartbeat,lease,release,transition,link,unlink,history,check-history}
    init                create the kernel schema in an empty destination
    health              schema version and basic counts
    expire-leases       sweep expired leases (never live ones)
    workflow            workflow registry
    create              create a work item
    show                show one work item
    list                find work; with no filter this lists EVERYTHING,
                        leased items included
    claim               acquire a lease
    heartbeat           extend a live lease you hold
    lease               who holds this item's lease, if anyone
    release             release a lease
    transition          make a validated transition
    link                create a typed link
    unlink              remove a typed link
    history             ordered event history (one page)
    check-history       check history read-only; exits 1 on drift

options:
  -h, --help            show this help message and exit
  --dsn DSN             PostgreSQL DSN (or set REGISTA_DSN)
  --schema SCHEMA       schema to use (default: public)
  --json                machine-readable output
```

## `regista init`

```text
usage: regista init [-h]

options:
  -h, --help  show this help message and exit
```

## `regista health`

```text
usage: regista health [-h]

options:
  -h, --help  show this help message and exit
```

## `regista expire-leases`

```text
usage: regista expire-leases [-h] [id]

positional arguments:
  id          sweep only this item's lease (default: all)

options:
  -h, --help  show this help message and exit
```

## `regista workflow`

```text
usage: regista workflow [-h] {register,validate,list,show} ...

positional arguments:
  {register,validate,list,show}
    register            register a workflow from a YAML or JSON document
    validate            check a workflow document; no database needed
    list                list registered workflows
    show                states, transitions, roles and required fields

options:
  -h, --help            show this help message and exit
```

## `regista workflow register`

```text
usage: regista workflow register [-h] --file FILE

options:
  -h, --help   show this help message and exit
  --file FILE
```

## `regista workflow validate`

```text
usage: regista workflow validate [-h] --file FILE

options:
  -h, --help   show this help message and exit
  --file FILE
```

## `regista workflow list`

```text
usage: regista workflow list [-h]

options:
  -h, --help  show this help message and exit
```

## `regista workflow show`

```text
usage: regista workflow show [-h] [--version VERSION] name

positional arguments:
  name

options:
  -h, --help         show this help message and exit
  --version VERSION  default: the latest registered
```

## `regista create`

```text
usage: regista create [-h] --workflow WORKFLOW --type TYPE --actor ACTOR [--actor-kind {agent,human,system}] [--field FIELD] [--idempotency-key IDEMPOTENCY_KEY]

options:
  -h, --help            show this help message and exit
  --workflow WORKFLOW
  --type TYPE
  --actor ACTOR
  --actor-kind {agent,human,system}
  --field FIELD         key=value, repeatable
  --idempotency-key IDEMPOTENCY_KEY
```

## `regista show`

```text
usage: regista show [-h] id

positional arguments:
  id

options:
  -h, --help  show this help message and exit
```

## `regista list`

```text
usage: regista list [-h] [--state STATE] [--workflow WORKFLOW] [--type TYPE] [--field FIELD] [--limit LIMIT] [--after AFTER] [--available | --owned OWNED | --blocked-by LINK_TYPE] [--direction {incoming,outgoing}] [--satisfied STATE]

options:
  -h, --help            show this help message and exit
  --state STATE         repeatable
  --workflow WORKFLOW
  --type TYPE           the caller's work-item type
  --field FIELD         key=value custom-field filter, repeatable, exact match
  --limit LIMIT
  --after AFTER         id of the last item of the previous page
  --available           only items with no LIVE lease
  --owned OWNED         only items leased by this actor
  --blocked-by LINK_TYPE
                        only items with an unsatisfied counterpart on this
                        link type; needs --satisfied
  --direction {incoming,outgoing}
                        which end of --blocked-by the counterpart is on
                        (default: incoming, i.e. the link points AT the item)
  --satisfied STATE     counterpart states that count as satisfied;
                        repeatable. Terminal is NOT satisfied — list
                        'rejected' only if a rejected counterpart really stops
                        blocking
```

## `regista claim`

```text
usage: regista claim [-h] --actor ACTOR [--ttl TTL] id

positional arguments:
  id

options:
  -h, --help     show this help message and exit
  --actor ACTOR
  --ttl TTL
```

## `regista heartbeat`

```text
usage: regista heartbeat [-h] --actor ACTOR --attempt ATTEMPT [--ttl TTL] id

positional arguments:
  id

options:
  -h, --help         show this help message and exit
  --actor ACTOR
  --attempt ATTEMPT
  --ttl TTL
```

## `regista lease`

```text
usage: regista lease [-h] id

positional arguments:
  id

options:
  -h, --help  show this help message and exit
```

## `regista release`

```text
usage: regista release [-h] --actor ACTOR --attempt ATTEMPT id

positional arguments:
  id

options:
  -h, --help         show this help message and exit
  --actor ACTOR
  --attempt ATTEMPT
```

## `regista transition`

```text
usage: regista transition [-h] --transition TRANSITION --actor ACTOR [--actor-kind {agent,human,system}] [--role ROLE] [--attempt ATTEMPT] [--field FIELD] [--unset-field KEY] [--idempotency-key IDEMPOTENCY_KEY] [--expected-seq EXPECTED_SEQ] id

positional arguments:
  id

options:
  -h, --help            show this help message and exit
  --transition TRANSITION
  --actor ACTOR
  --actor-kind {agent,human,system}
  --role ROLE
  --attempt ATTEMPT     fencing token; required under a live lease
  --field FIELD         key=value, repeatable
  --unset-field KEY     remove this custom field in the same write,
                        repeatable. The only way to clear one; recorded on the
                        event
  --idempotency-key IDEMPOTENCY_KEY
  --expected-seq EXPECTED_SEQ
```

## `regista link`

```text
usage: regista link [-h] --type TYPE source target

positional arguments:
  source
  target

options:
  -h, --help   show this help message and exit
  --type TYPE
```

## `regista unlink`

```text
usage: regista unlink [-h] --type TYPE source target

positional arguments:
  source
  target

options:
  -h, --help   show this help message and exit
  --type TYPE
```

## `regista history`

```text
usage: regista history [-h] [--limit LIMIT] [--after AFTER] [--before BEFORE] [--newest] id

positional arguments:
  id

options:
  -h, --help       show this help message and exit
  --limit LIMIT
  --after AFTER    seq of the last event of the previous page
  --before BEFORE  exclusive upper sequence bound
  --newest         select the newest matching suffix
```

## `regista check-history`

```text
usage: regista check-history [-h] [id]

positional arguments:
  id          omit to stream namespace replay (JSON Lines with --json)

options:
  -h, --help  show this help message and exit
```
