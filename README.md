# Regista

PostgreSQL coordination for applications that own their workers: versioned
workflows, work items, fenced leases, event history and read-only replay.

This branch is the Plan 032 scope cutover. The package version remains unchanged
pending F4/F5. Use a fresh PostgreSQL schema; existing pre-cutover stores are
refused and remain untouched. Actor IDs are caller attribution, and hashes check
consistency rather than identity. A lease fences writes to this store; callers
must handle external-effect deduplication themselves.

```bash
pip install regista-hraedon
regista --help
```

The install command applies to the eventual reduced release. To exercise this
candidate, install the locally built wheel instead.

```python
from regista import Kernel, Workflow

store = Kernel.connect("postgresql://user:password@localhost/database")
try:
    store.initialize()
    store.register_workflow(Workflow(
        name="tasks", types=("task",), states=("new", "done"), initial="new",
        transitions={"finish": (("new",), "done")}, terminal=("done",),
    ))
    item = store.create_work_item(workflow="tasks", type="task", actor_id="worker")
    lease = store.claim(item.id, actor_id="worker", ttl_seconds=300)
    store.transition(item.id, transition="finish", actor_id="worker", attempt=lease.attempt)
    store.release(item.id, actor_id="worker", attempt=lease.attempt)
    print(store.list_items(states=["done"]))
finally:
    store.close()
```

See [runnable examples](examples/README.md), [Plan 032](plans/032-final-public-release.md),
and the [Stage A protection ledger](plans/032-f0-inventory/F1-protection-ledger.md).
The [previous README](docs/pre-0.8/README.md) is historical. F4 will provide the
complete current API reference, preservation guidance and release notes.
