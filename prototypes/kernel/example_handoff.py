"""F0a scenario 1 — worker/reviewer handoff, contention, takeover, stale fencing.

Plan 032 F0a asks for a runnable scenario proving the coordination contract
through the proposed public API, with no mocks and no private imports. Workers
here are deterministic scripts on purpose: this validates agent-COMPATIBLE
coordination, not any model's behaviour.

Run:  python example_handoff.py "postgresql://user:pass@host/db"
"""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel import (
    ClaimContestedError,
    InvalidFieldError,
    Kernel,
    LeaseExpiredError,
    LeaseNotHeldError,
    StaleAttemptError,
    TransitionRefusedError,
    Workflow,
)

HERE = os.path.dirname(os.path.abspath(__file__))

REMEDIATION = Workflow(
    name="remediation",
    version=0,
    states=("open", "in_progress", "in_review", "changes_requested", "done"),
    initial="open",
    transitions={
        "start":           (("open", "changes_requested"), "in_progress"),
        "submit":          (("in_progress",), "in_review"),
        "request_changes": (("in_review",), "changes_requested"),
        "accept":          (("in_review",), "done"),
    },
    roles={"request_changes": ("reviewer",), "accept": ("reviewer",)},
    required_fields={"submit": ("remediation_note",)},
    terminal=("done",),
)


def step(n: str, msg: str) -> None:
    print(f"\n\033[1m{n}\033[0m {msg}")


def ok(msg: str) -> None:
    print(f"   \033[32m✓\033[0m {msg}")


def refused(msg: str) -> None:
    print(f"   \033[33m⊘ refused:\033[0m {msg}")


def _contender(
    dsn: str, item_id: str, actor: str, q: mp.Queue[tuple[str, str, object]]
) -> None:
    """A separate OS process racing for the same lease."""
    k = Kernel.connect(dsn)
    try:
        c = k.claim(uuid.UUID(item_id), actor_id=actor, ttl_seconds=300)
        q.put((actor, "won", c.attempt))
    except ClaimContestedError as e:
        q.put((actor, "lost", str(e)))
    finally:
        k.close()


def main(dsn: str) -> int:
    k = Kernel.connect(dsn)
    k.initialize(os.path.join(HERE, "schema.sql"))
    ok("connected and initialised — no keys, no trust log, no genesis ceremony")

    step("1.", "A discovery script files remediation work with domain fields and a link.")
    k.register_workflow(REMEDIATION)
    finding = k.create_work_item(
        workflow="remediation", type="finding", actor_id="scanner",
        fields={"host": "web-01", "cve": "CVE-2026-1337", "severity": "high"},
    )
    followup = k.create_work_item(
        workflow="remediation", type="followup", actor_id="scanner",
        fields={"host": "web-01", "note": "confirm patch after reboot"},
    )
    k.link(finding.id, followup.id, "blocks")
    ok(f"filed {finding.id} (state={finding.state}, cve={finding.fields['cve']})")
    ok(f"linked -> {followup.id} as 'blocks'")

    step("2.", "Two independently running worker processes contend. Only one may own it.")
    q: mp.Queue[tuple[str, str, object]] = mp.Queue()
    procs = [
        mp.Process(target=_contender, args=(dsn, str(finding.id), f"worker-{i}", q))
        for i in (1, 2)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    results = [q.get() for _ in procs]
    winners = [r for r in results if r[1] == "won"]
    for actor, outcome, detail in results:
        (ok if outcome == "won" else refused)(
            f"{actor}: {'holds attempt ' + str(detail) if outcome == 'won' else detail}"
        )
    assert len(winners) == 1, f"expected exactly one winner, got {results}"
    owner, _, attempt_obj = winners[0]
    attempt1 = int(attempt_obj)  # type: ignore[call-overload]
    ok(f"exactly one owner: {owner}, attempt {attempt1}")

    step("3.", "The owner works. A lease means the HOLDER writes — nobody else.")
    k.transition(finding.id, transition="start", actor_id=owner, attempt=attempt1)
    ok("start -> in_progress")
    try:
        k.transition(finding.id, transition="submit", actor_id=owner, attempt=attempt1)
    except InvalidFieldError as e:
        refused(f"submit without the required field: {e}")
    # Knowing the fencing token is not enough: the write must also be attributed
    # to the holder. Without this, any actor that saw an attempt number in a log
    # could write as though it owned the item.
    try:
        k.transition(finding.id, transition="submit", actor_id="worker-9", attempt=attempt1,
                     fields={"remediation_note": "written by someone who is not the holder"})
    except LeaseNotHeldError as e:
        refused(str(e))
    item = k.transition(
        finding.id, transition="submit", actor_id=owner, attempt=attempt1,
        fields={"remediation_note": "patched openssl to 3.0.14, rebooted"},
    )
    ok(f"submit -> {item.state} (note recorded)")
    k.release(finding.id, actor_id=owner, attempt=attempt1)
    ok("the owner released the lease — handing off means giving up ownership")

    step("4.", "The reviewer requests changes, with no lease of her own. Role policy holds.")
    try:
        k.transition(finding.id, transition="request_changes", actor_id="worker-9",
                     role="worker")
    except TransitionRefusedError as e:
        refused(str(e))
    # No attempt=: the item is unclaimed, and Plan 032 requires a person to be
    # able to act without first taking a lease.
    item = k.transition(finding.id, transition="request_changes", actor_id="alice",
                        actor_kind="human", role="reviewer",
                        payload={"comment": "confirm the service actually restarted"})
    ok(f"request_changes -> {item.state} (no claim needed)")

    step("5.", "The worker dies mid-attempt. Its lease expires and another worker takes over.")
    retry = k.claim(finding.id, actor_id=owner, ttl_seconds=2)
    k.transition(finding.id, transition="start", actor_id=owner, attempt=retry.attempt)
    ok(f"{owner} took another attempt {retry.attempt} (state=in_progress), then it died")
    # A real wait on a real short lease. Reaching into the table to backdate
    # expires_at would have been faster, but it would also have meant this
    # scenario no longer ran entirely through the public API.
    time.sleep(2.2)
    # Before anyone has swept or taken over, the dead worker's OWN lease is
    # already refused. An expired lease authorises nothing; that is what stops a
    # worker that merely slept past its TTL from committing.
    try:
        k.transition(finding.id, transition="submit", actor_id=owner, attempt=retry.attempt,
                     fields={"remediation_note": "woke up after the lease died"})
    except LeaseExpiredError as e:
        refused(str(e))
    swept = k.expire_leases()
    ok(f"lease expired and was swept ({swept} removed)")
    takeover = k.claim(finding.id, actor_id="worker-3", ttl_seconds=300)
    ok(f"worker-3 took over with attempt {takeover.attempt}")

    step("6.", "The dead worker wakes up and tries to commit. This is the fencing test.")
    try:
        k.transition(finding.id, transition="submit", actor_id=owner, attempt=retry.attempt,
                     fields={"remediation_note": "stale write from a zombie worker"})
        print("   \033[31m✗ THE STALE WRITE SUCCEEDED — fencing is broken\033[0m")
        return 1
    except StaleAttemptError as e:
        refused(str(e))
    ok("the stale attempt could not commit to this store")
    print("   \033[2m(note: a lease cannot stop that process making EXTERNAL requests —\033[0m")
    print("   \033[2m pass the attempt to the target system too if the effect"
          " must be fenced)\033[0m")

    step("7.", "The new worker finishes and a fresh review accepts it.")
    k.transition(finding.id, transition="submit", actor_id="worker-3",
                 attempt=takeover.attempt,
                 fields={"remediation_note": "verified openssl 3.0.14; nginx restarted"})
    k.release(finding.id, actor_id="worker-3", attempt=takeover.attempt)
    item = k.transition(finding.id, transition="accept", actor_id="alice",
                        actor_kind="human", role="reviewer")
    ok(f"accept -> {item.state}")
    try:
        k.transition(finding.id, transition="start", actor_id="worker-3")
    except TransitionRefusedError as e:
        refused(str(e))

    step("8.", "Discovery queries, over the caller's own workflow.")
    ok(f"available(open):      {len(k.available(states=('open',)))} item(s)")
    ok(f"owned(worker-3):      {len(k.owned('worker-3'))} item(s)")
    ok(f"in_states(in_review): {len(k.in_states(('in_review',)))} item(s)")
    ok(f"in_states(done):      {len(k.in_states(('done',)))} item(s)")
    ok(f"links_from(finding):  {k.links_from(finding.id)}")

    step("9.", "Replay rebuilds state from events alone.")
    state, fields, drift = k.replay(finding.id)
    ok(f"replayed state: {state}")
    ok(f"replayed fields: {sorted(fields)}")
    if drift:
        print(f"   \033[31m✗ drift: {drift}\033[0m")
        return 1
    ok("no drift between replay and projection; chain intact")

    step("10.", "The history a person actually reads.")
    for ev in k.history(finding.id):
        t = ev.transition or "created"
        print(f"   {ev.seq:>2}. {ev.occurred_at:%H:%M:%S}  {t:<16} "
              f"by {ev.actor_id:<10} ({ev.actor_kind})")

    k.close()
    print("\n\033[1;32mScenario passed.\033[0m")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
