"""F0a scenario 2 — non-agent document processing, a person acting via the CLI.

Plan 032 F0a requires this to use "the same public API and schema baseline with a
different workflow and field definitions" and to "add no document-specific code
to Regista". Nothing below imports a private name, and the kernel gained nothing
for documents: the only difference from scenario 1 is a JSON workflow and the
caller's own field names.

The person's steps genuinely shell out to cli.py, because Plan 032 requires that
"no HTTP service is required for a person to participate through the example CLI"
-- calling the library in-process would not have tested that.

Run:  python example_documents.py "postgresql://user:pass@host/db"
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel import InvalidFieldError, Kernel, TransitionRefusedError

HERE = os.path.dirname(os.path.abspath(__file__))

INGEST = {
    "name": "ingest",
    "states": ["received", "extracting", "needs_review", "rejected", "approved", "archived"],
    "initial": "received",
    "transitions": {
        "extract":  [["received"], "extracting"],
        "propose":  [["extracting"], "needs_review"],
        "correct":  [["needs_review"], "approved"],
        "reject":   [["needs_review"], "rejected"],
        "rework":   [["rejected"], "extracting"],
        "archive":  [["approved"], "archived"],
    },
    # Only a person may accept or reject an extraction. Application policy.
    "roles": {"correct": ["editor"], "reject": ["editor"]},
    "required_fields": {"propose": ["invoice_total", "invoice_date"]},
    "terminal": ["archived"],
}


def step(n: str, msg: str) -> None:
    print(f"\n\033[1m{n}\033[0m {msg}")


def ok(msg: str) -> None:
    print(f"   \033[32m✓\033[0m {msg}")


def refused(msg: str) -> None:
    print(f"   \033[33m⊘ refused:\033[0m {msg}")


def person(dsn: str, *argv: str) -> dict[str, Any]:
    """Run the CLI exactly as a person at a terminal would."""
    cmd = [sys.executable, os.path.join(HERE, "cli.py"), "--dsn", dsn, "--json", *argv]
    p = subprocess.run(cmd, capture_output=True, text=True)
    shown = " ".join(argv[:4])
    if p.returncode == 2:
        refused(f"$ regista-kernel {shown} -> {p.stderr.strip()}")
        return {}
    if p.returncode != 0:
        raise SystemExit(f"CLI failed: {p.stderr.strip()}")
    ok(f"$ regista-kernel {shown}")
    body: dict[str, Any] = json.loads(p.stdout) if p.stdout.strip() else {}
    return body


def counts(k: Kernel, actor: str) -> str:
    """The four discovery queries Plan 032 F0a asks to be exercised throughout."""
    return (
        f"available={len(k.available(states=('received',)))} "
        f"owned({actor})={len(k.owned(actor))} "
        f"blocked={len(k.in_states(('rejected',)))} "
        f"review_ready={len(k.in_states(('needs_review',)))}"
    )


def main(dsn: str) -> int:
    t0 = time.monotonic()
    k = Kernel.connect(dsn)
    k.initialize(os.path.join(HERE, "schema.sql"))

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(INGEST, fh)
        wf_path = fh.name
    person(dsn, "workflow", "register", "--file", wf_path)
    os.unlink(wf_path)
    ok("same kernel, same schema — only a different workflow document")

    step("1.", "An ingestion script files a document with a source reference and a follow-up.")
    doc = k.create_work_item(
        workflow="ingest", type="document", actor_id="ingest-cron", actor_kind="system",
        fields={"source_uri": "s3://invoices/2026-09/inv-8841.pdf", "pages": 3},
    )
    followup = k.create_work_item(
        workflow="ingest", type="followup", actor_id="ingest-cron", actor_kind="system",
        fields={"source_uri": "s3://invoices/2026-09/inv-8841.pdf",
                "note": "file the paper original"},
    )
    k.link(doc.id, followup.id, "follows")
    ok(f"document {doc.id} ({doc.state})")
    ok(f"linked -> {followup.id} as 'follows'")
    ok(counts(k, "ocr-worker"))

    step("2.", "A processing worker claims it and records extracted fields.")
    claim = k.claim(doc.id, actor_id="ocr-worker", ttl_seconds=300)
    k.transition(doc.id, transition="extract", actor_id="ocr-worker", attempt=claim.attempt)
    ok(f"extract -> extracting (attempt {claim.attempt})")
    ok(counts(k, "ocr-worker"))
    try:
        k.transition(doc.id, transition="propose", actor_id="ocr-worker",
                     attempt=claim.attempt, fields={"invoice_total": "1420.00"})
    except InvalidFieldError as e:
        refused(str(e))
    k.transition(
        doc.id, transition="propose", actor_id="ocr-worker", attempt=claim.attempt,
        fields={"invoice_total": "1420.00", "invoice_date": "2026-09-02",
                "confidence": 0.71},
    )
    ok("propose -> needs_review")
    k.release(claim.work_item_id, actor_id=claim.actor_id, attempt=claim.attempt)
    ok("worker released the lease so a person can act without a takeover")
    ok(counts(k, "ocr-worker"))

    step("3.", "A person reviews it through the CLI. Role policy holds against a human too.")
    person(dsn, "list", "--state", "needs_review")
    person(dsn, "show", str(doc.id))
    person(dsn, "transition", str(doc.id), "--transition", "reject",
           "--actor", "dave", "--actor-kind", "human", "--role", "clerk")
    out = person(dsn, "transition", str(doc.id), "--transition", "reject",
                 "--actor", "erin", "--actor-kind", "human", "--role", "editor",
                 "--field", "reject_reason=total read from the wrong column")
    ok(f"a person rejected it -> {out.get('state')}")
    ok(counts(k, "ocr-worker"))

    step("4.", "Rework, then the person corrects the value rather than rejecting again.")
    claim2 = k.claim(doc.id, actor_id="ocr-worker", ttl_seconds=300)
    k.transition(doc.id, transition="rework", actor_id="ocr-worker", attempt=claim2.attempt)
    k.transition(doc.id, transition="propose", actor_id="ocr-worker", attempt=claim2.attempt,
                 fields={"invoice_total": "1420.55", "confidence": 0.93})
    k.release(claim2.work_item_id, actor_id=claim2.actor_id, attempt=claim2.attempt)
    ok("re-proposed -> needs_review (invoice_date carried forward from the first attempt)")
    out = person(dsn, "transition", str(doc.id), "--transition", "correct",
                 "--actor", "erin", "--actor-kind", "human", "--role", "editor",
                 "--field", "invoice_total=1420.55", "--field", "corrected_by=erin")
    ok(f"a person approved it -> {out.get('state')}")
    ok(counts(k, "ocr-worker"))

    step("5.", "The external effect. This is the boundary Plan 032 insists on naming.")
    payment_key = f"pay:{doc.id}"
    ledger: dict[str, str] = {}

    def post_to_accounts(key: str, amount: str) -> str:
        """Stand-in for a downstream system. The DUPLICATE PROTECTION HERE IS ITS OWN."""
        if key in ledger:
            return f"already posted as {ledger[key]} (the ledger de-duplicated, not regista)"
        ledger[key] = f"txn-{len(ledger) + 1}"
        return f"posted {amount} as {ledger[key]}"

    item = k.get(doc.id)
    ok(post_to_accounts(payment_key, item.fields["invoice_total"]))
    ok(post_to_accounts(payment_key, item.fields["invoice_total"]))
    k.transition(doc.id, transition="archive", actor_id="ledger-worker",
                 idempotency_key=f"archive:{doc.id}",
                 fields={"payment_ref": ledger[payment_key]})
    k.transition(doc.id, transition="archive", actor_id="ledger-worker",
                 idempotency_key=f"archive:{doc.id}",
                 fields={"payment_ref": ledger[payment_key]})
    ok("the retried archive was a no-op — regista's idempotency key covered ITS write")
    print("   \033[2m the ledger post was protected by the LEDGER's own key. A regista"
          " lease or\033[0m")
    print("   \033[2m idempotency key never makes an external effect exactly-once.\033[0m")

    step("6.", "Terminal state, replay and the history a person reads.")
    try:
        k.transition(doc.id, transition="rework", actor_id="ocr-worker")
    except TransitionRefusedError as e:
        refused(str(e))
    state, fields, drift = k.replay(doc.id)
    ok(f"replayed state: {state}")
    ok(f"replayed fields: {sorted(fields)}")
    if drift:
        print(f"   \033[31m✗ drift: {drift}\033[0m")
        return 1
    ok("no drift; chain intact")
    person(dsn, "history", str(doc.id))
    for ev in k.history(doc.id):
        who = f"{ev.actor_id} ({ev.actor_kind})"
        print(f"   {ev.seq:>2}. {ev.transition or 'created':<10} {who}")

    elapsed = time.monotonic() - t0
    print(f"\n\033[1;32mScenario passed\033[0m in {elapsed:.1f}s from an empty database.")
    k.close()
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
