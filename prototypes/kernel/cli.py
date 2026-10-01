"""Small administration and participation CLI over the kernel.

Plan 032 keeps "a small initialization/workflow/inspection/replay/health CLI",
and requires that "the library and CLI must expose the same useful coordination
operations; no HTTP service is required for a person to participate through the
example CLI." This is that surface: it imports only the public kernel API and
adds no domain-specific behaviour of its own.

    export REGISTA_DSN="postgresql://..."
    python3 cli.py init
    python3 cli.py workflow validate --file workflow.yaml   # without a database
    python3 cli.py workflow register --file workflow.yaml
    python3 cli.py workflow show review
    python3 cli.py create --workflow review --type document --actor ingest --field src=s3://x
    python3 cli.py list                       # everything, leased items included
    python3 cli.py list --available           # only what has no live lease
    python3 cli.py list --field src=s3://x    # bounded custom-field filter
    python3 cli.py list --blocked-by blocks --direction incoming --satisfied approved
    python3 cli.py lease <id>
    python3 cli.py claim <id> --actor alice
    python3 cli.py heartbeat <id> --actor alice --attempt 1
    python3 cli.py transition <id> --transition approve --actor alice --role editor \
        --attempt 1 --unset-field draft_total
    python3 cli.py history <id>

Every listing is one PAGE. A full page prints a line saying so and how to
resume; it never silently stands in for the whole store.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel import (
    DEFAULT_PAGE_LIMIT,
    Claim,
    InvalidWorkflowError,
    Kernel,
    KernelError,
    Workflow,
    load_workflow,
    load_workflow_document,
    validate_workflow_document,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def _more(shown: int, limit: int, resume: str) -> None:
    """Say so when a page is full, instead of letting a bound look like the end.

    A truncated listing that says nothing is the same failure as a default
    listing that hides leased items: the answer looks complete and is not.
    """
    if shown >= limit:
        print(f"  … {limit} shown (the page limit); more may exist — {resume}")


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
    # No version= : the registry assigns it. Asserting one here would make every
    # registration from a file claim to be version 0.
    wf = load_workflow(args.file)
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
    held = k.lease(item.id)
    lease: dict[str, Any] | None = None
    if held is not None:
        lease = {"actor": held.actor_id, "attempt": held.attempt,
                 "expires_at": held.expires_at, "live": held.live}
    body = {"id": str(item.id), "workflow": f"{item.workflow_name} v{item.workflow_version}",
            "type": item.type, "state": item.state, "fields": item.fields,
            "last_event_seq": item.last_event_seq, "lease": lease,
            "links": [{"target": str(t), "type": lt} for t, lt in links]}
    if not args.json:
        print(f"  id      {item.id}")
        print(f"  state   {item.state}")
        print(f"  type    {item.type}")
        print(f"  lease   {_lease_line(held)}")
        for key, val in sorted(item.fields.items()):
            print(f"  · {key:<14} {val}")
        for t, lt in links:
            print(f"  -> {lt}: {t}")
    _emit(body, args.json)
    return 0


def _lease_line(held: Claim | None) -> str:
    """One line covering all three lease conditions, including the dead one."""
    if held is None:
        return "unclaimed (a write needs no --attempt)"
    when = f"{held.expires_at:%Y-%m-%d %H:%M:%S%z}"
    if held.live:
        return f"held by {held.actor_id} (attempt {held.attempt}) until {when}"
    return (f"EXPIRED — was held by {held.actor_id} (attempt {held.attempt}) until {when}; "
            "every write is refused until 'expire-leases' or a takeover")


def cmd_list(k: Kernel, args: argparse.Namespace) -> int:
    states = tuple(args.state or ())
    after = uuid.UUID(args.after) if args.after else None
    where = _fields(args.field) or None
    common: dict[str, Any] = {
        "workflow": args.workflow, "type": args.type, "where_fields": where,
        "limit": args.limit, "after": after,
    }
    if args.owned:
        items = k.owned(args.owned, states=states, **common)
    elif args.available:
        items = k.available(states=states, **common)
    elif args.blocked_by:
        if not args.satisfied:
            # The library allows satisfied_states=() and means it ("nothing
            # counts as satisfied"). At a terminal, an omitted --satisfied is
            # far likelier to be a forgotten argument than that intent, and the
            # result — every linked item reported as blocked — looks plausible.
            raise SystemExit(
                "--blocked-by needs at least one --satisfied STATE: which counterpart "
                "states mean 'no longer blocking'. A terminal state is not automatically "
                "one of them — a rejected blocker is terminal and still unsatisfied. "
                "Run 'workflow show <name>' to see the state names."
            )
        items = k.blocked(
            link_type=args.blocked_by, direction=args.direction,
            satisfied_states=tuple(args.satisfied or ()), states=states, **common,
        )
    else:
        # The default enumerates EVERYTHING, leased items included. A default
        # that quietly omitted them looked complete and was not.
        items = k.list_items(states=states, **common)
    out = [{"id": str(i.id), "state": i.state, "type": i.type, "fields": i.fields}
           for i in items]
    if not args.json:
        # One bounded count decides whether any row can be leased at all, so the
        # common case (no leases anywhere) costs one query instead of one per row.
        counts = k.health()
        leases_exist = int(counts["live_leases"]) + int(counts["expired_leases"]) > 0
        for i in items:
            # The id stays the first column: it is how a person pipes an id out
            # of this command. The lease marker goes last, after the fixed ones.
            held = k.lease(i.id) if leases_exist else None
            mark = "" if held is None else (
                f"  [leased by {held.actor_id}]" if held.live
                else f"  [lease EXPIRED, held by {held.actor_id}]"
            )
            print(f"  {i.id}  {i.state:<18} {i.type}{mark}")
        if not items:
            print("  (none)")
        _more(len(items), args.limit, f"resume with --after {items[-1].id}" if items else "")
    _emit(out, args.json)
    return 0


def cmd_claim(k: Kernel, args: argparse.Namespace) -> int:
    c = k.claim(uuid.UUID(args.id), actor_id=args.actor, ttl_seconds=args.ttl)
    if not args.json:
        print(f"attempt {c.attempt}, expires {c.expires_at:%Y-%m-%d %H:%M:%S%z}")
    _emit({"attempt": c.attempt, "expires_at": c.expires_at}, args.json)
    return 0


def cmd_heartbeat(k: Kernel, args: argparse.Namespace) -> int:
    """Extend a live lease. Without this, a person driving work through the CLI
    could take a lease in one invocation and had no way to keep it across the
    next few — the lease would die mid-task and refuse the write at the end."""
    c = k.heartbeat(uuid.UUID(args.id), actor_id=args.actor, attempt=args.attempt,
                    ttl_seconds=args.ttl)
    if not args.json:
        print(f"attempt {c.attempt} extended, expires {c.expires_at:%Y-%m-%d %H:%M:%S%z}")
    _emit({"attempt": c.attempt, "expires_at": c.expires_at, "live": c.live}, args.json)
    return 0


def cmd_lease(k: Kernel, args: argparse.Namespace) -> int:
    held = k.lease(uuid.UUID(args.id))
    if not args.json:
        print(f"  {_lease_line(held)}")
    _emit(None if held is None else
          {"actor": held.actor_id, "attempt": held.attempt,
           "expires_at": held.expires_at, "live": held.live}, args.json)
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
        fields=_fields(args.field), unset_fields=tuple(args.unset_field or ()),
        idempotency_key=args.idempotency_key,
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
    events = k.history(uuid.UUID(args.id), limit=args.limit, after=args.after)
    out = [{"seq": e.seq, "actor": e.actor_id, "actor_kind": e.actor_kind,
            "transition": e.transition, "payload": e.payload,
            "occurred_at": e.occurred_at} for e in events]
    if not args.json:
        for e in events:
            cleared = e.payload.get("unset")
            note = f"  (cleared {', '.join(cleared)})" if cleared else ""
            print(f"  {e.seq:>2}. {e.occurred_at:%Y-%m-%d %H:%M:%S}  "
                  f"{e.transition or 'created':<18} {e.actor_id} ({e.actor_kind}){note}")
        _more(len(events), args.limit,
              f"resume with --after {events[-1].seq}" if events else "")
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
    target = uuid.UUID(args.id) if args.id else None
    n = k.expire_leases(target)
    if not args.json:
        scope = f"on {args.id}" if target else "store-wide"
        print(f"{n} expired lease(s) swept ({scope}); live leases are never touched")
    _emit({"swept": n, "work_item_id": args.id}, args.json)
    return 0


def cmd_workflow_validate(args: argparse.Namespace) -> int:
    """Check a document without a database, and report EVERY problem at once.

    Deliberately outside the Kernel-taking dispatch table: validation touches no
    store, and requiring a DSN to spell-check a file would make the check
    unavailable exactly where it is most useful -- in an editor, in CI, before
    anything is provisioned.
    """
    try:
        doc = load_workflow_document(args.file)
        errors = list(validate_workflow_document(doc))
    except InvalidWorkflowError as e:
        # A parse failure (bad YAML, duplicate key, wrong extension) is a
        # problem with the document like any other, and belongs in the same
        # list rather than in a different exit path a caller has to know about.
        errors = [str(e)]
    if errors:
        if not args.json:
            print(f"\033[31m✗\033[0m {args.file}: {len(errors)} problem(s)")
            for message in errors:
                print(f"    - {message}")
        _emit({"file": args.file, "valid": False, "problems": errors}, args.json)
        return 1
    # from_document(), not the module-private builder: the F0a report records
    # that this CLI reaches for no private attribute, and that stays true.
    wf = Workflow.from_document(doc)
    if not args.json:
        print(f"\033[32m✓\033[0m {args.file}: {wf.name} — {len(wf.states)} states, "
              f"{len(wf.transitions)} transitions, types {sorted(wf.types)}")
    _emit({"file": args.file, "valid": True, "workflow": wf.name,
           "states": list(wf.states), "work_item_types": list(wf.types),
           "transitions": sorted(wf.transitions)}, args.json)
    return 0


def cmd_workflow_show(k: Kernel, args: argparse.Namespace) -> int:
    wf = k.get_workflow(args.name, args.version)
    body = {"name": wf.name, "version": wf.version, **wf.as_json()}
    if not args.json:
        print(f"  {wf.name} v{wf.version}")
        print(f"  initial  {wf.initial}")
        print(f"  states   {', '.join(wf.states)}")
        print(f"  terminal {', '.join(wf.terminal) or '(none)'}")
        # The declared sets, because both are CLOSED and create/transition
        # refuse anything outside them: a person told only the states would
        # have to discover the type list by being refused.
        print(f"  types    {', '.join(wf.types)}")
        print(f"  roles    {', '.join(wf.role_names) or '(none)'}")
        for name, (froms, to) in sorted(wf.transitions.items()):
            roles = wf.roles.get(name, ())
            need = wf.required_fields.get(name, ())
            extra = "".join([
                f"  roles={list(roles)}" if roles else "",
                f"  requires={list(need)}" if need else "",
            ])
            print(f"  · {name:<18} {list(froms)} -> {to}{extra}")
    _emit(body, args.json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="regista-kernel", description=__doc__.split("\n")[0])
    p.add_argument("--dsn", help="PostgreSQL DSN (or set REGISTA_DSN)")
    p.add_argument("--schema", default="public", help="schema to use (default: public)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the kernel schema in an empty destination")
    sub.add_parser("health", help="schema version and basic counts")
    xp = sub.add_parser("expire-leases", help="sweep expired leases (never live ones)")
    xp.add_argument("id", nargs="?", help="sweep only this item's lease (default: all)")

    wf = sub.add_parser("workflow", help="workflow registry").add_subparsers(
        dest="subcommand", required=True)
    wfr = wf.add_parser("register", help="register a workflow from a YAML or JSON document")
    wfr.add_argument("--file", required=True)
    wfv = wf.add_parser("validate", help="check a workflow document; no database needed")
    wfv.add_argument("--file", required=True)
    wf.add_parser("list", help="list registered workflows")
    wfs = wf.add_parser("show", help="states, transitions, roles and required fields")
    wfs.add_argument("name")
    wfs.add_argument("--version", type=int, help="default: the latest registered")

    c = sub.add_parser("create", help="create a work item")
    c.add_argument("--workflow", required=True)
    c.add_argument("--type", required=True)
    c.add_argument("--actor", required=True)
    c.add_argument("--actor-kind", default="agent", choices=["agent", "human", "system"])
    c.add_argument("--field", action="append", help="key=value, repeatable")

    s = sub.add_parser("show", help="show one work item")
    s.add_argument("id")

    ls = sub.add_parser(
        "list",
        help="find work; with no filter this lists EVERYTHING, leased items included",
    )
    ls.add_argument("--state", action="append", help="repeatable")
    ls.add_argument("--workflow")
    ls.add_argument("--type", help="the caller's work-item type")
    ls.add_argument("--field", action="append",
                    help="key=value custom-field filter, repeatable, exact match")
    ls.add_argument("--limit", type=int, default=DEFAULT_PAGE_LIMIT)
    ls.add_argument("--after", help="id of the last item of the previous page")
    scope = ls.add_mutually_exclusive_group()
    scope.add_argument("--available", action="store_true",
                       help="only items with no LIVE lease")
    scope.add_argument("--owned", help="only items leased by this actor")
    scope.add_argument("--blocked-by", metavar="LINK_TYPE",
                       help="only items with an unsatisfied counterpart on this link "
                            "type; needs --satisfied")
    ls.add_argument("--direction", default="incoming", choices=["incoming", "outgoing"],
                    help="which end of --blocked-by the counterpart is on "
                         "(default: incoming, i.e. the link points AT the item)")
    ls.add_argument("--satisfied", action="append", metavar="STATE",
                    help="counterpart states that count as satisfied; repeatable. "
                         "Terminal is NOT satisfied — list 'rejected' only if a "
                         "rejected counterpart really stops blocking")

    cl = sub.add_parser("claim", help="acquire a lease")
    cl.add_argument("id")
    cl.add_argument("--actor", required=True)
    cl.add_argument("--ttl", type=int, default=300)

    hb = sub.add_parser("heartbeat", help="extend a live lease you hold")
    hb.add_argument("id")
    hb.add_argument("--actor", required=True)
    hb.add_argument("--attempt", type=int, required=True)
    hb.add_argument("--ttl", type=int, default=300)

    le = sub.add_parser("lease", help="who holds this item's lease, if anyone")
    le.add_argument("id")

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
    t.add_argument("--unset-field", action="append", metavar="KEY",
                   help="remove this custom field in the same write, repeatable. "
                        "The only way to clear one; recorded on the event")
    t.add_argument("--idempotency-key")

    lk = sub.add_parser("link", help="create a typed link")
    lk.add_argument("source")
    lk.add_argument("target")
    lk.add_argument("--type", required=True)

    h = sub.add_parser("history", help="ordered event history (one page)")
    h.add_argument("id")
    h.add_argument("--limit", type=int, default=DEFAULT_PAGE_LIMIT)
    h.add_argument("--after", type=int, help="seq of the last event of the previous page")

    r = sub.add_parser("replay", help="rebuild state from events; exits 1 on drift")
    r.add_argument("id")
    return p


DISPATCH = {
    "init": cmd_init, "health": cmd_health, "expire-leases": cmd_expire,
    "create": cmd_create, "show": cmd_show, "list": cmd_list, "claim": cmd_claim,
    "heartbeat": cmd_heartbeat, "lease": cmd_lease,
    "release": cmd_release, "transition": cmd_transition, "link": cmd_link,
    "history": cmd_history, "replay": cmd_replay,
    ("workflow", "register"): cmd_workflow_register,
    # ("workflow", "validate") is NOT here: it runs without a Kernel.
    ("workflow", "list"): cmd_workflow_list,
    ("workflow", "show"): cmd_workflow_show,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    key: Any = args.command
    if args.command == "workflow":
        key = (args.command, args.subcommand)
        if args.subcommand == "validate":
            # Before _kernel(): no DSN, no connection, no schema. A document is
            # checkable on a laptop with nothing provisioned.
            return cmd_workflow_validate(args)
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
