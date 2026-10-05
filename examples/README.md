# Runnable 0.8.0 coordination examples

Install the candidate wheel (or, after publication, `pip install regista-hraedon`).
Use PostgreSQL 15 and an **empty disposable database per scenario**. No keys,
private configuration or checkout on the import path are needed. The unchanged
scripts and YAML files are packaged under `regista/examples`; tests pin them to
the source copies in this directory.

To extract and run the installed resources, from any scratch directory:

```bash
python - <<'PY'
from importlib.resources import files
from pathlib import Path
source = files("regista").joinpath("examples")
Path("examples").mkdir(exist_ok=True)
for name in ("example_handoff.py", "example_documents.py",
             "remediation.workflow.yaml", "ingest.workflow.yaml"):
    Path("examples", name).write_bytes(source.joinpath(name).read_bytes())
PY
regista --help
python examples/example_handoff.py "$HANDOFF_DSN"
python examples/example_documents.py "$DOCUMENTS_DSN"
```

[Worker/reviewer handoff](example_handoff.py) races two processes, records results,
requests changes, models a dead worker by waiting for real lease expiry, takes
over, refuses stale attempts and completes fresh review. F3 additionally terminates
an actual lease-holding process and proves takeover. The script itself does not
terminate that process.

[Document processing](example_documents.py) uses a distinct workflow, fields and
links, and human correction through `python -m regista.cli` from the installed
package. Both exercise discovery and replay. Fields merge shallowly;
`unset_fields` removes keys. Leases persist until explicit release. Stable keys
deduplicate Regista writes; the illustrative downstream accounts ledger provides
its own duplicate protection and is not durable production infrastructure.

[Quickstart](quickstart.py) is the exact tested README example. Set `REGISTA_DSN`
and optionally `REGISTA_SCHEMA` (default `tasks`). The
[original F0a fit report](../plans/032-f0-inventory/F0a-report.md) records the original
walkthrough; [F3 qualification](../plans/032-f3-qualification.md) records artifact runs.
