"""Non-agent document processing over the same regista coordination kernel.

Story: an ingestion step files a document item and a follow-up item, linking
them. The follow-up is scheduled for later. A processing worker records
extracted fields, a person corrects them, and the document is committed. Work
is discovered with claimable/owned/review-ready queries.

Run against disposable Postgres:

    PYTHONPATH=src .venv/bin/python examples/document_processing.py [DSN] [PROJECT]

The default DSN is the repository test database. If PROJECT is omitted a unique
disposable project name is generated. No keys or suite configuration are used.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from regista import ErrorCode, Regista, RegistaError

DEFAULT_DSN = os.environ.get(
    "REGISTA_EXAMPLE_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
WORKFLOW_PATH = Path(__file__).with_name("document_processing.yaml")


def _load_workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _show(label: str, sub: Regista, **query: object) -> list:
    page = sub.query_work_items(**query)
    print(f"[query] {label}: {len(page.items)} item(s)")
    for work_item in page.items:
        print(
            f"    {work_item.work_item_id} type={work_item.work_item_type} "
            f"state={work_item.current_state} claimed_by={work_item.claimed_by}"
        )
    return page.items


def main(dsn: str, project: str | None = None) -> int:
    project = project or f"ex_docs_{uuid.uuid4().hex[:10]}"
    print(f"[setup] disposable project: {project}")
    print(f"[setup] dsn: {dsn}")

    sub = Regista.create_project(dsn, project)
    try:
        sub.register_workflow(_load_workflow())
        print("[setup] workflow 'document_processing' v1 registered")

        document, _ = sub.create_work_item(
            "document_processing",
            "document",
            "ingester",
            custom_fields={
                "source_ref": "s3://incoming/invoice-77.pdf",
                "document_type": "invoice",
            },
        )
        follow_up, _ = sub.create_work_item(
            "document_processing",
            "follow_up",
            "ingester",
            custom_fields={
                "title": "Verify totals against the purchase order",
                "detail": "Invoice total differs from PO by 3%.",
            },
            not_before=datetime.now(UTC) + timedelta(hours=1),
        )
        sub.create_link(document.work_item_id, follow_up.work_item_id, "follows", "ingester")
        print(f"[ingest] document {document.work_item_id}")
        print(f"[ingest] follow-up {follow_up.work_item_id} (scheduled for later)")
        for link in sub.list_links(document.work_item_id):
            print(
                f"[ingest] link {link.link_type}: "
                f"{link.from_work_item_id} -> {link.to_work_item_id}"
            )

        _show(
            "claimable 'ingested' work",
            sub,
            current_states=["ingested"],
            claimable_now=True,
        )
        _show("owned work", sub, claimed_by="processor-1")
        _show("review-ready work", sub, current_states=["needs_review"])

        try:
            sub.acquire_claim(follow_up.work_item_id, "processor-1")
            print("[schedule] ERROR: future follow-up was claimable")
            return 1
        except RegistaError as exc:
            if exc.code != ErrorCode.NOT_BEFORE_FUTURE:
                raise
            print(f"[schedule] follow-up refused while not_before is in the future: {exc.code}")

        sub.update_not_before(follow_up.work_item_id, None, "ingester")
        print("[schedule] cleared the follow-up's not_before gate")
        _show(
            "claimable 'ingested' work after reschedule",
            sub,
            current_states=["ingested"],
            claimable_now=True,
        )

        claim = sub.acquire_claim(document.work_item_id, "processor-1", ttl_seconds=300)
        print(f"[process] processor-1 claimed attempt {claim.attempt_number}")

        extracted = {
            "vendor": "Acme Supply",
            "invoice_no": "INV-77",
            "total": 1250.0,
            "currency": "USD",
        }
        sub.transition(
            document.work_item_id,
            "extract",
            "processor-1",
            actor_metadata={"role": "processor"},
            custom_fields={"extracted": extracted, "confidence": 91},
            expected_attempt_number=claim.attempt_number,
        )
        sub.transition(
            document.work_item_id,
            "submit_for_review",
            "processor-1",
            actor_metadata={"role": "processor"},
            expected_attempt_number=claim.attempt_number,
        )
        print("[process] extracted fields recorded and submitted for review")

        _show("review-ready work", sub, current_states=["needs_review"])

        corrected = dict(extracted, total=1180.5)
        sub.transition(
            document.work_item_id,
            "correct",
            "reviewer-1",
            actor_kind="human",
            actor_metadata={"role": "reviewer"},
            custom_fields={
                "extracted": corrected,
                "review_note": "Total corrected against the purchase order.",
            },
        )
        print("[review] reviewer corrected the extracted total through a transition")

        sub.transition(
            document.work_item_id,
            "commit",
            "reviewer-1",
            actor_kind="human",
            actor_metadata={"role": "reviewer"},
        )
        print("[review] reviewer committed the document")

        final = sub.get_work_item(document.work_item_id)
        assert final is not None
        print(
            f"[final] state={final.current_state} "
            f"extracted={final.custom_fields.get('extracted')}"
        )

        _show(
            "invoices",
            sub,
            custom_field_filters={"document_type": "invoice"},
        )

        print("[history] events for the document item:")
        for event in sub.read_events(work_item_id=document.work_item_id):
            print(
                f"    seq={event.event_seq:<2} "
                f"transition={event.transition!r} actor={event.actor_id}"
            )

        report = sub.replay()
        print(
            f"[replay] ok={report.replayed_ok} drift={report.replayed_drift} "
            f"halted={report.halted}"
        )
        print(
            "[summary] document committed after machine extraction and a human "
            "correction, discovered through claimable/owned/review-ready queries."
        )
        print(
            "[caveat] A regista lease grants durable ownership, not exactly-once "
            "downstream effects. Give any external write a stable application key."
        )
        return 0
    finally:
        sub.close()


if __name__ == "__main__":
    argv = sys.argv[1:]
    sys.exit(main(argv[0] if argv else DEFAULT_DSN, argv[1] if len(argv) > 1 else None))
