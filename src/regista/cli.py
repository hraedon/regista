"""Small administration and participation CLI over the kernel.

Plan 032 keeps "a small initialization/workflow/inspection/replay/health CLI",
and requires that "the library and CLI must expose the same useful coordination
operations; no HTTP service is required for a person to participate through the
example CLI." This is that surface: it imports only the public kernel API and
adds no domain-specific behaviour of its own.

    export REGISTA_DSN="postgresql://..."
    regista init
    regista workflow validate --file workflow.yaml   # without a database
    regista workflow register --file workflow.yaml
    regista workflow show review
    regista create --workflow review --type document --actor ingest --field src=s3://x
    regista list                       # everything, leased items included
    regista list --available           # only what has no live lease
    regista list --field src=s3://x    # bounded custom-field filter
    regista list --blocked-by blocks --direction incoming --satisfied approved
    regista lease <id>
    regista claim <id> --actor alice
    regista heartbeat <id> --actor alice --attempt 1
    regista transition <id> --transition approve --actor alice --role editor \
        --attempt 1 --unset-field draft_total
    regista history <id>

Every listing is one PAGE. A full page prints a line saying so and how to
resume; it never silently stands in for the whole store.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import traceback
import uuid
from typing import Any, NoReturn

from . import (
    DEFAULT_PAGE_LIMIT,
    Claim,
    InvalidFieldError,
    InvalidWorkflowError,
    Kernel,
    KernelError,
    Workflow,
    load_workflow,
    load_workflow_document,
    validate_workflow_document,
)

HERE = os.path.dirname(os.path.abspath(__file__))


def _escape_human(value: object) -> str:
    """Render caller/stored values without terminal, line or bidi controls."""
    out: list[str] = []
    for char in str(value):
        code = ord(char)
        if code < 0x20 or 0x7f <= code <= 0x9f or code in {
            0x061c, 0x200e, 0x200f, 0x2028, 0x2029,
            0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
            0x2066, 0x2067, 0x2068, 0x2069,
        }:
            out.append({10: r"\n", 13: r"\r", 9: r"\t"}.get(
                code, f"\\u{code:04x}"))
        else:
            out.append(char)
    return "".join(out)


def _human(value: object, *, file: Any = None) -> None:
    print(_escape_human(value), file=file)


class _RefusalParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise InvalidFieldError(message)


def _uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a UUID") from exc


def _refusal(error: KernelError, as_json: bool) -> int:
    _human(f"refused: {error}", file=sys.stderr)
    _emit({"error": type(error).__name__, "message": str(error), "exit_code": 2}, as_json)
    return 2


def _more(shown: int, limit: int, resume: str) -> None:
    """Say so when a page is full, instead of letting a bound look like the end.

    A truncated listing that says nothing is the same failure as a default
    listing that hides leased items: the answer looks complete and is not.
    """
    if shown >= limit:
        _human(f"  … {limit} shown (the page limit); more may exist — {resume}")


def _fields(pairs: list[str] | None) -> dict[str, Any]:
    """--field k=v, repeatable. Values parse as JSON when they can, else stay text."""
    out: dict[str, Any] = {}
    for p in pairs or []:
        if "=" not in p:
            raise InvalidFieldError(f"--field expects key=value, got {p!r}")
        k, v = p.split("=", 1)
        try:
            out[k] = json.loads(v)
        except json.JSONDecodeError:
            out[k] = v
        except (ValueError, RecursionError) as exc:
            raise InvalidFieldError("--field JSON exceeds parser limits") from exc
    return out


def _kernel(args: argparse.Namespace) -> Kernel:
    dsn = args.dsn or os.environ.get("REGISTA_DSN")
    if not dsn:
        raise KernelError("no DSN: pass --dsn or set REGISTA_DSN")
    return Kernel.connect(dsn, schema=args.schema, require_existing=args.command != "init")


def _emit(obj: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))


def cmd_init(k: Kernel, args: argparse.Namespace) -> int:
    k.initialize()
    if not args.json:
        _human(f"initialised schema {args.schema!r}")
    _emit({"schema": args.schema, "status": "ready"}, args.json)
    return 0


def cmd_health(k: Kernel, args: argparse.Namespace) -> int:
    state = k.health()
    if not args.json:
        for key, val in state.items():
            _human(f"  {key:<16} {val}")
    _emit(state, args.json)
    return 0


def cmd_workflow_register(k: Kernel, args: argparse.Namespace) -> int:
    # No version= : the registry assigns it. Asserting one here would make every
    # registration from a file claim to be version 0.
    wf = load_workflow(args.file)
    version = k.register_workflow(wf)
    if not args.json:
        _human(f"{wf.name} registered at version {version}")
    _emit({"workflow": wf.name, "version": version}, args.json)
    return 0


def cmd_workflow_list(k: Kernel, args: argparse.Namespace) -> int:
    out = [{"name": n, "version": v, "registered_at": at}
           for n, v, at in k.list_workflows()]
    if not args.json:
        for r in out:
            _human(f"  {r['name']:<24} v{r['version']}")
    _emit(out, args.json)
    return 0


def cmd_create(k: Kernel, args: argparse.Namespace) -> int:
    item = k.create_work_item(
        workflow=args.workflow, type=args.type, actor_id=args.actor,
        actor_kind=args.actor_kind, fields=_fields(args.field),
        idempotency_key=args.idempotency_key,
    )
    if not args.json:
        _human(f"{item.id}  {item.state}")
    _emit({"id": str(item.id), "state": item.state, "fields": item.fields}, args.json)
    return 0


def cmd_show(k: Kernel, args: argparse.Namespace) -> int:
    item = k.get(args.id)
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
        _human(f"  id      {item.id}")
        _human(f"  workflow {item.workflow_name} v{item.workflow_version}")
        _human(f"  state   {item.state}")
        _human(f"  type    {item.type}")
        _human(f"  lease   {_lease_line(held)}")
        for key, val in sorted(item.fields.items()):
            _human(f"  · {key:<14} {val}")
        for t, lt in links:
            _human(f"  -> {lt}: {t}")
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
    after = args.after if args.after else None
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
            raise InvalidFieldError(
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
            _human(f"  {i.id}  {i.state:<18} {i.type}  "
                  f"{i.workflow_name} v{i.workflow_version}{mark}")
        if not items:
            _human("  (none)")
        _more(len(items), args.limit, f"resume with --after {items[-1].id}" if items else "")
    _emit(out, args.json)
    return 0


def cmd_claim(k: Kernel, args: argparse.Namespace) -> int:
    c = k.claim(args.id, actor_id=args.actor, ttl_seconds=args.ttl)
    if not args.json:
        _human(f"attempt {c.attempt}, expires {c.expires_at:%Y-%m-%d %H:%M:%S%z}")
    _emit({"attempt": c.attempt, "expires_at": c.expires_at}, args.json)
    return 0


def cmd_heartbeat(k: Kernel, args: argparse.Namespace) -> int:
    """Extend a live lease. Without this, a person driving work through the CLI
    could take a lease in one invocation and had no way to keep it across the
    next few — the lease would die mid-task and refuse the write at the end."""
    c = k.heartbeat(args.id, actor_id=args.actor, attempt=args.attempt,
                    ttl_seconds=args.ttl)
    if not args.json:
        _human(f"attempt {c.attempt} extended, expires {c.expires_at:%Y-%m-%d %H:%M:%S%z}")
    _emit({"attempt": c.attempt, "expires_at": c.expires_at, "live": c.live}, args.json)
    return 0


def cmd_lease(k: Kernel, args: argparse.Namespace) -> int:
    held = k.lease(args.id)
    if not args.json:
        _human(f"  {_lease_line(held)}")
    _emit(None if held is None else
          {"actor": held.actor_id, "attempt": held.attempt,
           "expires_at": held.expires_at, "live": held.live}, args.json)
    return 0


def cmd_release(k: Kernel, args: argparse.Namespace) -> int:
    k.release(args.id, actor_id=args.actor, attempt=args.attempt)
    if not args.json:
        _human("released")
    _emit({"released": args.id}, args.json)
    return 0


def cmd_transition(k: Kernel, args: argparse.Namespace) -> int:
    item = k.transition(
        args.id, transition=args.transition, actor_id=args.actor,
        actor_kind=args.actor_kind, role=args.role, attempt=args.attempt,
        fields=_fields(args.field), unset_fields=tuple(args.unset_field or ()),
        idempotency_key=args.idempotency_key, expected_seq=args.expected_seq,
    )
    if not args.json:
        _human(f"{args.transition} -> {item.state}")
    _emit({"id": str(item.id), "state": item.state, "fields": item.fields}, args.json)
    return 0


def cmd_link(k: Kernel, args: argparse.Namespace) -> int:
    k.link(args.source, args.target, args.type)
    if not args.json:
        _human(f"{args.source} -{args.type}-> {args.target}")
    _emit({"source": args.source, "target": args.target, "type": args.type}, args.json)
    return 0


def cmd_unlink(k: Kernel, args: argparse.Namespace) -> int:
    k.remove_link(args.source, args.target, args.type)
    if not args.json:
        _human(f"absent {args.source} -{args.type}-> {args.target}")
    _emit({"source": args.source, "target": args.target, "type": args.type}, args.json)
    return 0


def cmd_history(k: Kernel, args: argparse.Namespace) -> int:
    events = k.history(args.id, limit=args.limit, after=args.after,
                       before=args.before, newest=args.newest)
    out = [{"seq": e.seq, "actor": e.actor_id, "actor_kind": e.actor_kind,
            "transition": e.transition, "payload": e.payload,
            "occurred_at": e.occurred_at} for e in events]
    if not args.json:
        for e in events:
            cleared = e.payload.get("unset")
            note = f"  (cleared {', '.join(cleared)})" if cleared else ""
            _human(f"  {e.seq:>2}. {e.occurred_at:%Y-%m-%d %H:%M:%S}  "
                  f"{e.transition or 'created':<18} {e.actor_id} ({e.actor_kind}){note}")
        resume = ""
        if events:
            resume = (f"resume with --before {events[0].seq}" if args.newest
                      else f"resume with --after {events[-1].seq}")
        _more(len(events), args.limit, resume)
    _emit(out, args.json)
    return 0


def cmd_replay(k: Kernel, args: argparse.Namespace) -> int:
    if args.id is None:
        failed = False
        for report in k.replay_all():
            failed |= bool(report.drift)
            if args.json:
                print(json.dumps({"work_item_id": str(report.work_item_id),
                                  "state": report.state, "fields": report.fields,
                                  "drift": report.drift}, default=str))
            else:
                _human(f"  {report.work_item_id}  state {report.state}  "
                      f"drift {report.drift or 'none'}")
        return 1 if failed else 0
    state, fields, drift = k.replay(args.id)
    if not args.json:
        _human(f"  state  {state}")
        for key, val in sorted(fields.items()):
            _human(f"  · {key:<14} {val}")
        _human(f"  drift  {drift or 'none'}")
    _emit({"state": state, "fields": fields, "drift": drift}, args.json)
    return 1 if drift else 0


def cmd_expire(k: Kernel, args: argparse.Namespace) -> int:
    target = args.id if args.id else None
    n = k.expire_leases(target)
    if not args.json:
        scope = f"on {args.id}" if target else "store-wide"
        _human(f"{n} expired lease(s) swept ({scope}); live leases are never touched")
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
            _human(f"✗ {args.file}: {len(errors)} problem(s)")
            for message in errors:
                _human(f"    - {message}")
        _emit({"file": args.file, "valid": False, "problems": errors}, args.json)
        return 1
    # from_document(), not the module-private builder: the F0a report records
    # that this CLI reaches for no private attribute, and that stays true.
    wf = Workflow.from_document(doc)
    if not args.json:
        _human(f"✓ {args.file}: {wf.name} — {len(wf.states)} states, "
              f"{len(wf.transitions)} transitions, types {sorted(wf.types)}")
    _emit({"file": args.file, "valid": True, "workflow": wf.name,
           "states": list(wf.states), "work_item_types": list(wf.types),
           "transitions": sorted(wf.transitions)}, args.json)
    return 0


def cmd_workflow_show(k: Kernel, args: argparse.Namespace) -> int:
    wf = k.get_workflow(args.name, args.version)
    body = {"name": wf.name, "version": wf.version, **wf.as_json()}
    if not args.json:
        _human(f"  {wf.name} v{wf.version}")
        _human(f"  initial  {wf.initial}")
        _human(f"  states   {', '.join(wf.states)}")
        _human(f"  terminal {', '.join(wf.terminal) or '(none)'}")
        # The declared sets, because both are CLOSED and create/transition
        # refuse anything outside them: a person told only the states would
        # have to discover the type list by being refused.
        _human(f"  types    {', '.join(wf.types)}")
        _human(f"  roles    {', '.join(wf.role_names) or '(none)'}")
        for name, (froms, to) in sorted(wf.transitions.items()):
            roles = wf.roles.get(name, ())
            need = wf.required_fields.get(name, ())
            extra = "".join([
                f"  roles={list(roles)}" if roles else "",
                f"  requires={list(need)}" if need else "",
            ])
            _human(f"  · {name:<18} {list(froms)} -> {to}{extra}")
    _emit(body, args.json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = _RefusalParser(prog="regista", description=__doc__.split("\n")[0])
    p.add_argument("--dsn", help="PostgreSQL DSN (or set REGISTA_DSN)")
    p.add_argument("--schema", default="public", help="schema to use (default: public)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create the kernel schema in an empty destination")
    sub.add_parser("health", help="schema version and basic counts")
    xp = sub.add_parser("expire-leases", help="sweep expired leases (never live ones)")
    xp.add_argument("id", type=_uuid, nargs="?", help="sweep only this item's lease (default: all)")

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
    c.add_argument("--idempotency-key")

    s = sub.add_parser("show", help="show one work item")
    s.add_argument("id", type=_uuid)

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
    ls.add_argument("--after", type=_uuid, help="id of the last item of the previous page")
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
    cl.add_argument("id", type=_uuid)
    cl.add_argument("--actor", required=True)
    cl.add_argument("--ttl", type=int, default=300)

    hb = sub.add_parser("heartbeat", help="extend a live lease you hold")
    hb.add_argument("id", type=_uuid)
    hb.add_argument("--actor", required=True)
    hb.add_argument("--attempt", type=int, required=True)
    hb.add_argument("--ttl", type=int, default=300)

    le = sub.add_parser("lease", help="who holds this item's lease, if anyone")
    le.add_argument("id", type=_uuid)

    rl = sub.add_parser("release", help="release a lease")
    rl.add_argument("id", type=_uuid)
    rl.add_argument("--actor", required=True)
    rl.add_argument("--attempt", type=int, required=True)

    t = sub.add_parser("transition", help="make a validated transition")
    t.add_argument("id", type=_uuid)
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
    t.add_argument("--expected-seq", type=int)

    lk = sub.add_parser("link", help="create a typed link")
    lk.add_argument("source", type=_uuid)
    lk.add_argument("target", type=_uuid)
    lk.add_argument("--type", required=True)

    ul = sub.add_parser("unlink", help="remove a typed link")
    ul.add_argument("source", type=_uuid)
    ul.add_argument("target", type=_uuid)
    ul.add_argument("--type", required=True)

    h = sub.add_parser("history", help="ordered event history (one page)")
    h.add_argument("id", type=_uuid)
    h.add_argument("--limit", type=int, default=DEFAULT_PAGE_LIMIT)
    h.add_argument("--after", type=int, help="seq of the last event of the previous page")

    r = sub.add_parser("check-history", help="check history read-only; exits 1 on drift")
    h.add_argument("--before", type=int, help="exclusive upper sequence bound")
    h.add_argument("--newest", action="store_true", help="select the newest matching suffix")
    r.add_argument("id", type=_uuid, nargs="?",
                   help="omit to stream namespace replay (JSON Lines with --json)")
    return p


DISPATCH = {
    "init": cmd_init, "health": cmd_health, "expire-leases": cmd_expire,
    "create": cmd_create, "show": cmd_show, "list": cmd_list, "claim": cmd_claim,
    "heartbeat": cmd_heartbeat, "lease": cmd_lease,
    "release": cmd_release, "transition": cmd_transition, "link": cmd_link,
    "unlink": cmd_unlink,
    "history": cmd_history, "check-history": cmd_replay,
    ("workflow", "register"): cmd_workflow_register,
    # ("workflow", "validate") is NOT here: it runs without a Kernel.
    ("workflow", "list"): cmd_workflow_list,
    ("workflow", "show"): cmd_workflow_show,
}


class _HumanLogFilter(logging.Filter):
    """Pool diagnostics carry caller/server text through the human renderer too."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _escape_human(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = _escape_human("".join(traceback.format_exception(*record.exc_info)))
        return True


_HUMAN_LOG_FILTER = _HumanLogFilter()


def main(argv: list[str] | None = None) -> int:
    logging.getLogger("psycopg.pool").addFilter(_HUMAN_LOG_FILTER)
    supplied = sys.argv[1:] if argv is None else argv
    if "replay" in supplied:
        # argparse rejects the removed command; explain the semantic break too.
        # Detect command position with parse_known_args, rather than matching data.
        probe = _RefusalParser(add_help=False)
        probe.add_argument("--dsn")
        probe.add_argument("--schema")
        probe.add_argument("--json", action="store_true")
        try:
            _, remaining = probe.parse_known_args(supplied)
        except KernelError as exc:
            return _refusal(exc, "--json" in supplied)
        if remaining and remaining[0] == "replay":
            return _refusal(InvalidFieldError(
                "the old replay command rebuilt projections and is removed. "
                "Use check-history for the new read-only consistency check."), "--json" in supplied)
    try:
        args = build_parser().parse_args(supplied)
    except KernelError as exc:
        return _refusal(exc, "--json" in supplied)
    key: Any = args.command
    if args.command == "workflow":
        key = (args.command, args.subcommand)
        if args.subcommand == "validate":
            # Before _kernel(): no DSN, no connection, no schema. A document is
            # checkable on a laptop with nothing provisioned.
            return cmd_workflow_validate(args)
    handler = DISPATCH[key]
    k: Kernel | None = None
    try:
        k = _kernel(args)
        return handler(k, args)
    except KernelError as e:
        # Refusals are the product working, so they print cleanly and exit 2.
        return _refusal(e, args.json)
    finally:
        if k is not None:
            k.close()


if __name__ == "__main__":
    sys.exit(main())
