"""Worker/reviewer handoff over the regista coordination kernel.

Story: a discovery step files remediation work and links it to two related
items. Two worker processes race to own the item; the loser is refused. The
winner performs an external side effect and hands the item to a reviewer. The
reviewer requests changes, the worker takes a new attempt, and a stale attempt
is refused. A fresh review completes the item.

Run against disposable Postgres:

    PYTHONPATH=src .venv/bin/python examples/worker_reviewer.py [DSN] [PROJECT]

The default DSN is the repository test database. If PROJECT is omitted a unique
disposable project name is generated. No keys or suite configuration are used.
"""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

from regista import ErrorCode, Regista, RegistaError

DEFAULT_DSN = os.environ.get(
    "REGISTA_EXAMPLE_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
WORKFLOW_PATH = Path(__file__).with_name("workflow_worker_reviewer.yaml")


class DownstreamLedger:
    """A toy external system that de-duplicates by a caller-supplied key.

    This models the part of exactly-once that regista does NOT provide: if the
    external effect succeeds but the caller crashes before recording it, a
    retry re-runs the call. The downstream system must recognise the stable
    operation key and make the repeat a no-op.
    """

    def __init__(self) -> None:
        self._applied: dict[str, str] = {}

    def apply(self, operation_key: str, description: str) -> bool:
        if operation_key in self._applied:
            return False
        self._applied[operation_key] = description
        return True

    @property
    def effects(self) -> dict[str, str]:
        return dict(self._applied)


def _load_workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def _print_links(sub: Regista, work_item_id: uuid.UUID) -> None:
    for link in sub.list_links(work_item_id):
        print(
            f"    link {link.link_type}: {link.from_work_item_id} -> "
            f"{link.to_work_item_id}"
        )


def main(dsn: str, project: str | None = None) -> int:
    project = project or f"ex_worker_{uuid.uuid4().hex[:10]}"
    print(f"[setup] disposable project: {project}")
    print(f"[setup] dsn: {dsn}")

    sub = Regista.create_project(dsn, project)
    try:
        sub.register_workflow(_load_workflow())
        print("[setup] workflow 'remediation' v1 registered")

        prerequisite, _ = sub.create_work_item(
            "remediation",
            "remediation",
            "discovery",
            custom_fields={
                "title": "Add regression test for the crash",
                "source_ref": "incident://INC-1042/test-gap",
                "severity": "medium",
            },
        )
        item, _ = sub.create_work_item(
            "remediation",
            "remediation",
            "discovery",
            custom_fields={
                "title": "Fix null dereference in request handler",
                "source_ref": "incident://INC-1042",
                "severity": "high",
            },
        )
        dependent, _ = sub.create_work_item(
            "remediation",
            "remediation",
            "discovery",
            custom_fields={
                "title": "Re-deploy after fix is accepted",
                "source_ref": "deploy://svc-http",
                "severity": "high",
            },
        )
        sub.create_link(item.work_item_id, prerequisite.work_item_id, "follows", "discovery")
        sub.create_link(item.work_item_id, dependent.work_item_id, "blocks", "discovery")
        print(f"[discovery] filed remediation {item.work_item_id}")
        _print_links(sub, item.work_item_id)

        available = sub.query_work_items(
            workflow_name="remediation",
            current_states=["ready"],
            claimable_now=True,
        )
        print(f"[discovery] claimable 'ready' items: {len(available.items)}")

        worker_a = "worker-a"
        worker_b = "worker-b"
        claim_a = sub.acquire_claim(item.work_item_id, worker_a, ttl_seconds=120)
        print(
            f"[race] {worker_a} acquired attempt {claim_a.attempt_number} "
            f"(expires {claim_a.expires_at.isoformat()})"
        )
        try:
            sub.acquire_claim(item.work_item_id, worker_b, ttl_seconds=120)
            print(f"[race] ERROR: {worker_b} unexpectedly acquired the item")
            return 1
        except RegistaError as exc:
            if exc.code != ErrorCode.CLAIM_CONTESTED:
                raise
            print(f"[race] {worker_b} refused: {exc.code}")

        ledger = DownstreamLedger()
        operation_key = f"remediation:{item.work_item_id}"
        result = "Guarded the null path and added a unit test"
        first = ledger.apply(operation_key, result)
        second = ledger.apply(operation_key, result)
        print(
            f"[effect] downstream apply first={first} replay={second} "
            f"(application key={operation_key})"
        )

        sub.transition(
            item.work_item_id,
            "start",
            worker_a,
            actor_metadata={"role": "worker"},
            expected_attempt_number=claim_a.attempt_number,
        )
        sub.transition(
            item.work_item_id,
            "submit_for_review",
            worker_a,
            actor_metadata={"role": "worker"},
            custom_fields={"result": result},
            expected_attempt_number=claim_a.attempt_number,
        )
        print("[handoff] worker transitioned the item to in_review")

        sub.transition(
            item.work_item_id,
            "request_changes",
            "reviewer-1",
            actor_metadata={"role": "reviewer"},
            payload={"diagnostics": {"kind": "review_fail", "summary": "edge case missing"}},
        )
        print("[review] reviewer requested changes (item back in in_progress)")

        claim_b = sub.acquire_claim(item.work_item_id, worker_a, ttl_seconds=120)
        print(f"[retry] worker re-acquired as attempt {claim_b.attempt_number}")

        try:
            sub.transition(
                item.work_item_id,
                "submit_for_review",
                worker_a,
                actor_metadata={"role": "worker"},
                expected_attempt_number=claim_a.attempt_number,
            )
            print("[retry] ERROR: stale attempt was accepted")
            return 1
        except RegistaError as exc:
            if exc.code != ErrorCode.CLAIM_LOST:
                raise
            print(
                f"[retry] stale attempt {claim_a.attempt_number} refused: {exc.code} "
                f"(current attempt {claim_b.attempt_number})"
            )

        sub.transition(
            item.work_item_id,
            "submit_for_review",
            worker_a,
            actor_metadata={"role": "worker"},
            custom_fields={"result": result + "; addressed edge case"},
            expected_attempt_number=claim_b.attempt_number,
        )
        sub.transition(
            item.work_item_id,
            "approve",
            "reviewer-1",
            actor_metadata={"role": "reviewer"},
            custom_fields={"result": result + "; addressed edge case"},
        )
        print("[review] reviewer approved the item")

        final = sub.get_work_item(item.work_item_id)
        assert final is not None
        print(f"[final] state={final.current_state} attempt={final.attempt_number}")

        print("[history] events for the remediation item:")
        for event in sub.read_events(work_item_id=item.work_item_id):
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
            "[summary] remediation reached 'done' after a contested claim, one "
            "change request, and a refused stale attempt."
        )
        print(
            "[caveat] A regista lease grants durable ownership, not exactly-once "
            "downstream effects. The application's stable operation key above is "
            "what prevents a duplicate external effect."
        )
        return 0
    finally:
        sub.close()


if __name__ == "__main__":
    argv = sys.argv[1:]
    sys.exit(main(argv[0] if argv else DEFAULT_DSN, argv[1] if len(argv) > 1 else None))
