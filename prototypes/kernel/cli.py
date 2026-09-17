"""Small administration and participation CLI over the kernel.

Plan 032 keeps "a small initialization/workflow/inspection/replay/health CLI",
and requires that "the library and CLI must expose the same useful coordination
operations; no HTTP service is required for a person to participate through the
example CLI." This is that surface: it imports only the public kernel API and
adds no domain-specific behaviour of its own.

    export REGISTA_DSN="postgresql://..."
    python cli.py init
    python cli.py workflow register --file workflow.json
    python cli.py create --workflow review --type document --actor ingest --field src=s3://x
    python cli.py list --available
    python cli.py claim <id> --actor alice
    python cli.py transition <id> --transition approve --actor alice --role editor --attempt 1
    python cli.py history <id>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel import Kernel, KernelError, Workflow

HERE = os.path.dirname(os.path.abspath(__file__))


def _fields(pairs: list[str] | None) -> dict[str, Any]:
    """--field k=v, repeatable. Values parse as JSON when they can, else stay text."""
    out: dict[str, Any] = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"--field expects key=value, got {p!r}")
        k, v = p.split("=", 1)
        try:
            out[k] = json.loads(v)
        except json.JSONDecodeError:
            out[k] = v
    return out


def _kernel(args: argparse.Namespace) -> Kernel:
    dsn = args.dsn or os.environ.get("REGISTA_DSN")
    if not dsn:
        raise SystemExit("no DSN: pass --dsn or set REGISTA_DSN")
    return Kernel.connect(dsn, schema=args.schema)


def _emit(obj: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))


def cmd_init(k: Kernel, args: argparse.Namespace) -> int:
    k.initialize(os.path.join(HERE, "schema.sql"))
    if not args.json:
        print(f"initialised schema {args.schema!r}")
    _emit({"schema": args.schema, "status": "ready"}, args.json)
    return 0


def cmd_health(k: Kernel, args: argparse.Namespace) -> int:
    state = k.health()
    if not args.json:
        for key, val in state.items():
            print(f"  {key:<16} {val}")
    _emit(state, args.json)
    return 0


def cmd_workflow_register(k: Kernel, args: argparse.Namespace) -> int:
    with open(args.file) as fh:
        body = json.load(fh)
    wf = Workflow.from_json(body, version=0)
    version = k.register_workflow(wf)
    if not args.json:
        print(f"{wf.name} registered at version {version}")
    _emit({"workflow": wf.name, "version": version}, args.json)
    return 0


def cmd_workflow_list(k: Kernel, args: argparse.Namespace) -> int:
    out = [{"name": n, "version": v, "registered_at": at}
           for n, v, at in k.list_workflows()]
    if not args.json:
        for r in out:
            print(f"  {r['name']:<24} v{r['version']}")
    _emit(out, args.json)
    return 0


def cmd_create(k: Kernel, args: argparse.Namespace) -> int:
    item = k.create_work_item(
        workflow=args.workflow, type=args.type, actor_id=args.actor,
        actor_kind=args.actor_kind, fields=_fields(args.field),
    )
    if not args.json:
        print(f"{item.id}  {item.state}")
    _emit({"id": str(item.id), "state": item.state, "fields": item.fields}, args.json)
    return 0


def cmd_show(k: Kernel, args: argparse.Namespace) -> int:
    item = k.get(uuid.UUID(args.id))
    links = k.links_from(item.id)
    body = {"id": str(item.id), "workflow": f"{item.workflow_name} v{item.workflow_version}",
            "type": item.type, "state": item.state, "fields": item.fields,
            "last_event_seq": item.last_event_seq,
            "links": [{"target": str(t), "type": lt} for t, lt in links]}
    if not args.json:
        print(f"  id      {item.id}")
        print(f"  state   {item.state}")
        print(f"  type    {item.type}")
        for key, val in sorted(item.fields.items()):
            print(f"  · {key:<14} {val}")
        for t, lt in links:
            print(f"  -> {lt}: {t}")
    _emit(body, args.json)
    return 0


def cmd_list(k: Kernel, args: argparse.Namespace) -> int:
    states = tuple(args.state or ())
    if args.owned:
        items = k.owned(args.owned, limit=args.limit)
    elif args.available:
        items = k.available(workflow=args.workflow, states=states, limit=args.limit)
    else:
        items = k.in_states(states, limit=args.limit) if states else k.available(
            workflow=args.workflow, limit=args.limit)
    out = [{"id": str(i.id), "state": i.state, "type": i.type, "fields": i.fields}
           for i in items]
    if not args.json:
        for i in items:
            print(f"  {i.id}  {i.state:<18} {i.type}")
        if not items:
            print("  (none)")
    _emit(out, args.json)
    return 0


def cmd_claim(k: Kernel, args: argparse.Namespace) -> int:
    c = k.claim(uuid.UUID(args.id), actor_id=args.actor, ttl_seconds=args.ttl)
    if not args.json:
        print(f"attempt {c.attempt}, expires {c.expires_at:%Y-%m-%d %H:%M:%S%z}")
    _emit({"attempt": c.attempt, "expires_at": c.expires_at}, args.json)
    return 0


def cmd_release(k: Kernel, args: argparse.Namespace) -> int:
    k.release(uuid.UUID(args.id), actor_id=args.actor, attempt=args.attempt)
    if not args.json:
        print("released")
    _emit({"released": args.id}, args.json)
    return 0


def cmd_transition(k: Kernel, args: argparse.Namespace) -> int:
    item = k.transition(
        uuid.UUID(args.id), transition=args.transition, actor_id=args.actor,
        actor_kind=args.actor_kind, role=args.role, attempt=args.attempt,
        fields=_fields(args.field), idempotency_key=args.idempotency_key,
    )
    if not args.json:
        print(f"{args.transition} -> {item.state}")
    _emit({"id": str(item.id), "state": item.state, "fields": item.fields}, args.json)
    return 0


def cmd_link(k: Kernel, args: argparse.Namespace) -> int:
    k.link(uuid.UUID(args.source), uuid.UUID(args.target), args.type)
    if not args.json:
        print(f"{args.source} -{args.type}-> {args.target}")
    _emit({"source": args.source, "target": args.target, "type": args.type}, args.json)
    return 0


def cmd_history(k: Kernel, args: argparse.Namespace) -> int:
    events = k.history(uuid.UUID(args.id))
    out = [{"seq": e.seq, "actor": e.actor_id, "actor_kind": e.actor_kind,
            "transition": e.transition, "payload": e.payload,
            "occurred_at": e.occurred_at} for e in events]
    if not args.json:
        for e in events:
            print(f"  {e.seq:>2}. {e.occurred_at:%Y-%m-%d %H:%M:%S}  "
                  f"{e.transition or 'created':<18} {e.actor_id} ({e.actor_kind})")
    _emit(out, args.json)
    return 0


def cmd_replay(k: Kernel, args: argparse.Namespace) -> int:
    state, fields, drift = k.replay(uuid.UUID(args.id))
    if not args.json:
        print(f"  state  {state}")
        for key, val in sorted(fields.items()):
            print(f"  · {key:<14} {val}")
        print(f"  drift  {drift or 'none'}")
    _emit({"state": state, "fields": fields, "drift": drift}, args.json)
    return 1 if drift else 0


def cmd_expire(k: Kernel, args: argparse.Namespace) -> int:
    n = k.expire_leases()
    if not args.json:
        print(f"{n} expired lease(s) swept")
    _emit({"swept": n}, args.json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="regista-kernel", description=__doc__.split("\n")[0])
    p.add_argument("--dsn", help="PostgreSQL DSN (or set REGISTA_DSN)")
    p.add_argument("--schema", default="public", help="schema to use (default: public)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the kernel schema in an empty destination")
    sub.add_parser("health", help="schema version and basic counts")
    sub.add_parser("expire-leases", help="sweep expired leases")

    wf = sub.add_parser("workflow", help="workflow registry").add_subparsers(
        dest="subcommand", required=True)
    wfr = wf.add_parser("register", help="register a workflow from JSON")
    wfr.add_argument("--file", required=True)
    wf.add_parser("list", help="list registered workflows")

    c = sub.add_parser("create", help="create a work item")
    c.add_argument("--workflow", required=True)
    c.add_argument("--type", required=True)
    c.add_argument("--actor", required=True)
    c.add_argument("--actor-kind", default="agent", choices=["agent", "human", "system"])
    c.add_argument("--field", action="append", help="key=value, repeatable")

    s = sub.add_parser("show", help="show one work item")
    s.add_argument("id")

    ls = sub.add_parser("list", help="find work")
    ls.add_argument("--state", action="append", help="repeatable")
    ls.add_argument("--available", action="store_true", help="exclude items under a live lease")
    ls.add_argument("--owned", help="items leased by this actor")
    ls.add_argument("--workflow")
    ls.add_argument("--limit", type=int, default=50)

    cl = sub.add_parser("claim", help="acquire a lease")
    cl.add_argument("id")
    cl.add_argument("--actor", required=True)
    cl.add_argument("--ttl", type=int, default=300)

    rl = sub.add_parser("release", help="release a lease")
    rl.add_argument("id")
    rl.add_argument("--actor", required=True)
    rl.add_argument("--attempt", type=int, required=True)

    t = sub.add_parser("transition", help="make a validated transition")
    t.add_argument("id")
    t.add_argument("--transition", required=True)
    t.add_argument("--actor", required=True)
    t.add_argument("--actor-kind", default="agent", choices=["agent", "human", "system"])
    t.add_argument("--role")
    t.add_argument("--attempt", type=int, help="fencing token; required under a live lease")
    t.add_argument("--field", action="append", help="key=value, repeatable")
    t.add_argument("--idempotency-key")

    lk = sub.add_parser("link", help="create a typed link")
    lk.add_argument("source")
    lk.add_argument("target")
    lk.add_argument("--type", required=True)

    h = sub.add_parser("history", help="ordered event history")
    h.add_argument("id")

    r = sub.add_parser("replay", help="rebuild state from events; exits 1 on drift")
    r.add_argument("id")
    return p


DISPATCH = {
    "init": cmd_init, "health": cmd_health, "expire-leases": cmd_expire,
    "create": cmd_create, "show": cmd_show, "list": cmd_list, "claim": cmd_claim,
    "release": cmd_release, "transition": cmd_transition, "link": cmd_link,
    "history": cmd_history, "replay": cmd_replay,
    ("workflow", "register"): cmd_workflow_register,
    ("workflow", "list"): cmd_workflow_list,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    key: Any = args.command
    if args.command == "workflow":
        key = (args.command, args.subcommand)
    handler = DISPATCH[key]
    k = _kernel(args)
    try:
        return handler(k, args)
    except KernelError as e:
        # Refusals are the product working, so they print cleanly and exit 2.
        print(f"refused: {e}", file=sys.stderr)
        return 2
    finally:
        k.close()


if __name__ == "__main__":
    sys.exit(main())
