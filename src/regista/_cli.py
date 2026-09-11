from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from regista import Regista
from regista._errors import RegistaError
from regista._workflow import validate_yaml as _validate_yaml

#: Transient failures a caller may reasonably retry (suite CLI contract v1 §3).
_RETRYABLE_CODES = frozenset({"CLAIM_CONTESTED", "CONCURRENT_MODIFICATION"})


def _add_conn_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dsn", default=argparse.SUPPRESS, help="Postgres DSN (or REGISTA_DSN)")
    parser.add_argument(
        "--project",
        default=argparse.SUPPRESS,
        help="Project schema name (or REGISTA_PROJECT)",
    )


def _add_json_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )


def _resolve_config(args: argparse.Namespace) -> tuple[str | None, str | None]:
    dsn = getattr(args, "dsn", None) or os.environ.get("REGISTA_DSN")
    project = getattr(args, "project", None) or os.environ.get("REGISTA_PROJECT")
    return dsn, project


def _require_config(args: argparse.Namespace) -> tuple[str, str]:
    dsn, project = _resolve_config(args)
    missing = []
    if not dsn:
        missing.append("--dsn or REGISTA_DSN")
    if not project:
        missing.append("--project or REGISTA_PROJECT")
    if missing:
        print(f"Missing required config: {', '.join(missing)}", file=sys.stderr)
        raise SystemExit(2)
    assert dsn is not None
    assert project is not None
    return dsn, project


def _dump_json(obj: Any) -> None:
    if hasattr(obj, "to_dict"):
        data = obj.to_dict()
    elif isinstance(obj, list):
        data = [item.to_dict() if hasattr(item, "to_dict") else item for item in obj]
    else:
        data = obj
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def _error_envelope(e: RegistaError) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": str(e.code),
            "message": e.message,
            "detail": (
                None if e.detail is None else json.dumps(e.detail, sort_keys=True, default=str)
            ),
            "retryable": str(e.code) in _RETRYABLE_CODES,
            "partial": None,
        },
    }


def _handle_error(e: RegistaError, json_mode: bool = False) -> int:
    if json_mode:
        print(json.dumps(_error_envelope(e), indent=2))
    print(f"[{e.code}] {e.message}", file=sys.stderr)
    return 1


def _parse_uuid(value: str, label: str = "work item ID") -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        print(f"Invalid {label}: {value!r}", file=sys.stderr)
        raise SystemExit(1) from None


def _parse_json_arg(value: str | None, label: str) -> Any:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON for {label}: {e}", file=sys.stderr)
        raise SystemExit(1) from None


def _parse_iso_arg(value: str | None, label: str) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        print(f"Invalid timestamp for {label}: {value!r}", file=sys.stderr)
        raise SystemExit(1) from None


# ---------------------------------------------------------------------------
# workflow
# ---------------------------------------------------------------------------


def cmd_workflow_validate(args: argparse.Namespace) -> int:
    if args.path == "-":
        raw = sys.stdin.read()
    else:
        source = Path(args.path)
        if not source.is_file():
            print(f"workflow file not found: {args.path}", file=sys.stderr)
            return 1
        raw = source.read_text()
    try:
        result = _validate_yaml(raw)
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    if getattr(args, "json", False):
        _dump_json(result)
    elif result.valid:
        assert result.workflow is not None
        print(f"Valid: {result.workflow.name} v{result.workflow.version}")
    else:
        for err in result.errors:
            print(f"  {err.path}: {err.message}")
    return 0 if result.valid else 1


# ---------------------------------------------------------------------------
# work-item
# ---------------------------------------------------------------------------


def cmd_work_item_show(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    work_item_id = _parse_uuid(args.work_item_id)
    try:
        with Regista(dsn, project) as sub:
            wi = sub.get_work_item(work_item_id)
            if wi is None:
                print(f"Work item {args.work_item_id!r} not found", file=sys.stderr)
                return 1
            if getattr(args, "json", False):
                _dump_json(wi)
            else:
                print(f"WorkItem {wi.work_item_id}")
                print(f"  workflow: {wi.workflow_name} v{wi.workflow_version}")
                print(f"  type:     {wi.work_item_type}")
                print(f"  state:    {wi.current_state}")
                print(f"  seq:      {wi.last_event_seq}")
                print(f"  claimed:  {wi.claimed_by or '(none)'}")
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    return 0


def cmd_work_item_list(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    collected = []
    cursor = None
    try:
        with Regista(dsn, project) as sub:
            while True:
                page = sub.query_work_items(
                    workflow_name=args.workflow,
                    current_states=args.state,
                    claimed_by=args.claimed_by,
                    claimable_now=True if args.claimable_now else None,
                    needs_review=True if args.needs_review else None,
                    cursor=cursor,
                    page_size=args.page_size,
                )
                collected.extend(page.items)
                if args.limit is not None and len(collected) >= args.limit:
                    collected = collected[: args.limit]
                    break
                if not page.has_more:
                    break
                cursor = page.cursor
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    if getattr(args, "json", False):
        _dump_json({"items": collected, "count": len(collected)})
    else:
        for item in collected:
            print(
                f"{str(item.work_item_id)[:8]}  "
                f"{item.workflow_name:20s} "
                f"{item.current_state:12s} "
                f"{item.work_item_type}"
            )
    return 0


def cmd_work_item_create(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    custom_fields = _parse_json_arg(args.custom_fields, "--custom-fields")
    not_before = _parse_iso_arg(args.not_before, "--not-before")
    try:
        with Regista(dsn, project) as sub:
            wi, evt = sub.create_work_item(
                workflow_name=args.workflow,
                work_item_type=args.type,
                actor_id=args.actor_id,
                custom_fields=custom_fields,
                not_before=not_before,
            )
            if getattr(args, "json", False):
                _dump_json({"work_item": wi, "event": evt})
            else:
                print(f"Created {wi.work_item_id}")
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    return 0


def cmd_work_item_transition(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    work_item_id = _parse_uuid(args.work_item_id)
    payload = _parse_json_arg(args.payload, "--payload")
    custom_fields = _parse_json_arg(args.custom_fields, "--custom-fields")
    try:
        with Regista(dsn, project) as sub:
            evt = sub.transition(
                work_item_id,
                args.transition,
                args.actor_id,
                payload=payload,
                custom_fields=custom_fields,
                expected_attempt_number=args.expected_attempt_number,
            )
            if getattr(args, "json", False):
                _dump_json(evt)
            else:
                print(f"Transitioned: seq={evt.event_seq}")
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    return 0


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------


def cmd_events_show(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    work_item_id = _parse_uuid(args.work_item_id)
    try:
        with Regista(dsn, project) as sub:
            events = sub.read_events(
                work_item_id=work_item_id,
                actor_id=args.actor_id,
                transition=args.transition,
                limit=args.limit,
                before_seq=args.before_seq,
            )
            if getattr(args, "json", False):
                _dump_json(events)
            else:
                for e in events:
                    print(
                        f"seq={e.event_seq:<4} {e.timestamp.isoformat()}  "
                        f"{e.transition or '(none)'}"
                    )
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    return 0


def cmd_events_tail(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    try:
        with Regista(dsn, project) as sub:
            events = sub.read_events(
                actor_id=args.actor_id,
                transition=args.transition,
                limit=args.limit,
            )
            if getattr(args, "json", False):
                _dump_json(events)
            else:
                for e in events:
                    print(
                        f"{e.work_item_id}  seq={e.event_seq}  "
                        f"{e.timestamp.isoformat()}  {e.transition or '(none)'}"
                    )
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    return 0


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


def cmd_replay(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    work_item_id = (
        _parse_uuid(args.work_item_id) if args.work_item_id else None
    )
    try:
        with Regista(dsn, project) as sub:
            report = sub.replay(work_item_id=work_item_id)
            if getattr(args, "json", False):
                _dump_json(report)
            else:
                print(
                    f"ok={report.replayed_ok}  drift={report.replayed_drift}  "
                    f"halted={report.halted}  warnings={report.warnings}"
                )
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    if report.replayed_drift > 0 or report.halted > 0:
        return 1
    return 0


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------


def cmd_schema_init(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    try:
        Regista.create_project(dsn, project).close()
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    print(f"Schema initialized for project {project!r}")
    return 0


def cmd_schema_status(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    from regista._connection import ConnectionManager
    from regista._migrations import check_migrations_current
    from regista._version_info import SCHEMA_VERSION

    mgr = ConnectionManager(dsn, project)
    try:
        mgr.open()
        check_migrations_current(mgr)
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        mgr.close()
    if getattr(args, "json", False):
        _dump_json({"project": project, "schema_version": SCHEMA_VERSION, "current": True})
    else:
        print(f"project={project}")
        print(f"schema_version={SCHEMA_VERSION}")
        print("status=current")
    return 0


# ---------------------------------------------------------------------------
# actor-roles
# ---------------------------------------------------------------------------


def cmd_actor_roles_list(args: argparse.Namespace) -> int:
    dsn, project = _require_config(args)
    from regista._actor_roles import list_actor_roles
    from regista._connection import ConnectionManager

    mgr = ConnectionManager(dsn, project)
    try:
        mgr.open()
        with mgr.connect() as conn:
            rows = list_actor_roles(conn, args.actor_id)
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        mgr.close()
    if getattr(args, "json", False):
        _dump_json(rows)
    else:
        for r in rows:
            print(f"{r['actor_id']:20s} {r['role']:20s} {r['created_at'].isoformat()}")
    return 0


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


def cmd_version(args: argparse.Namespace) -> int:
    from regista._version_info import versions

    info = versions()
    if getattr(args, "json", False):
        _dump_json(info)
    else:
        print(f"regista {info.library_version}")
        print(f"  schema_version:          {info.schema_version}")
        print(f"  canonical_workflow_ver:  {info.canonical_workflow_version}")
        print(f"  canonical_workflow_hash: {info.canonical_workflow_hash}")
    return 0


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    from regista._doctor import run_doctor

    dsn, project = _resolve_config(args)
    try:
        report = run_doctor(
            dsn,
            project=project,
            max_projects=args.max_projects,
        )
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))
    if getattr(args, "json", False):
        _dump_json(report)
    else:
        print(f"component: {report.component}")
        print(f"version:   {report.version}")
        print(f"reachable: {report.reachable}")
        if report.schema_version is not None:
            print(f"schema:    {report.schema_version}")
        if report.projects:
            print(f"projects:  {', '.join(p['name'] for p in report.projects)}")
        print()
        for check in report.checks:
            print(f"  [{check.status:>4}] {check.name}: {check.detail}")
    if any(c.status == "fail" for c in report.checks):
        return 1
    return 0


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="regista", description="Regista admin CLI")
    parser.add_argument("--dsn", help="Postgres DSN (or REGISTA_DSN)")
    parser.add_argument("--project", help="Project schema name (or REGISTA_PROJECT)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    subs = parser.add_subparsers(dest="command")

    wf = subs.add_parser("workflow", help="Workflow commands")
    wf_sub = wf.add_subparsers(dest="subcommand")
    wf_val = wf_sub.add_parser("validate", help="Validate workflow YAML")
    wf_val.add_argument("path", help="Path to YAML file, or - for stdin")
    wf_val.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )
    wf_val.set_defaults(func=cmd_workflow_validate)

    wi = subs.add_parser("work-item", help="Work item commands")
    wi_sub = wi.add_subparsers(dest="subcommand")
    wi_show = wi_sub.add_parser("show", help="Show a work item")
    wi_show.add_argument("work_item_id", help="Work item UUID")
    _add_conn_args(wi_show)
    _add_json_arg(wi_show)
    wi_show.set_defaults(func=cmd_work_item_show)

    wi_list = wi_sub.add_parser("list", help="List work items")
    wi_list.add_argument("--workflow", help="Filter by workflow name")
    wi_list.add_argument("--state", action="append", help="Filter by state (repeatable)")
    wi_list.add_argument("--claimed-by", help="Filter by claiming actor")
    wi_list.add_argument("--claimable-now", action="store_true", help="Filter claimable now")
    wi_list.add_argument("--needs-review", action="store_true", help="Filter needs review")
    wi_list.add_argument("--limit", type=int, default=None, help="Maximum rows to return")
    wi_list.add_argument("--page-size", type=int, default=100, help="Query page size")
    _add_conn_args(wi_list)
    _add_json_arg(wi_list)
    wi_list.set_defaults(func=cmd_work_item_list)

    wi_create = wi_sub.add_parser("create", help="Create a work item")
    wi_create.add_argument("--workflow", required=True, help="Workflow name")
    wi_create.add_argument("--type", required=True, help="Work item type")
    wi_create.add_argument("--actor-id", required=True, help="Actor ID")
    wi_create.add_argument("--custom-fields", help="Custom fields (JSON)")
    wi_create.add_argument("--not-before", help="ISO 8601 timestamp")
    _add_conn_args(wi_create)
    _add_json_arg(wi_create)
    wi_create.set_defaults(func=cmd_work_item_create)

    wi_trans = wi_sub.add_parser("transition", help="Transition a work item")
    wi_trans.add_argument("work_item_id", help="Work item UUID")
    wi_trans.add_argument("--transition", required=True, help="Transition name")
    wi_trans.add_argument("--actor-id", required=True, help="Actor ID")
    wi_trans.add_argument("--payload", help="Transition payload (JSON)")
    wi_trans.add_argument("--custom-fields", help="Custom fields update (JSON)")
    wi_trans.add_argument(
        "--expected-attempt-number", type=int, default=None, help="Fence against a stolen lease"
    )
    _add_conn_args(wi_trans)
    _add_json_arg(wi_trans)
    wi_trans.set_defaults(func=cmd_work_item_transition)

    ev = subs.add_parser("events", help="Event commands")
    ev_sub = ev.add_subparsers(dest="subcommand")
    ev_show = ev_sub.add_parser("show", help="Show events for a work item")
    ev_show.add_argument("--work-item-id", required=True, help="Work item UUID")
    ev_show.add_argument("--actor-id", help="Filter by actor_id")
    ev_show.add_argument("--transition", help="Filter by transition name")
    ev_show.add_argument("--limit", type=int, default=100)
    ev_show.add_argument("--before-seq", type=int, default=None)
    _add_conn_args(ev_show)
    _add_json_arg(ev_show)
    ev_show.set_defaults(func=cmd_events_show)

    ev_tail = ev_sub.add_parser("tail", help="Tail events across items")
    ev_tail.add_argument("--actor-id", help="Filter by actor_id")
    ev_tail.add_argument("--transition", help="Filter by transition name")
    ev_tail.add_argument("--limit", type=int, default=100)
    _add_conn_args(ev_tail)
    _add_json_arg(ev_tail)
    ev_tail.set_defaults(func=cmd_events_tail)

    rep = subs.add_parser("replay", help="Run replay drift check")
    rep.add_argument("--work-item-id", default=None, help="Scope replay to one work item")
    _add_conn_args(rep)
    _add_json_arg(rep)
    rep.set_defaults(func=cmd_replay)

    sc = subs.add_parser("schema", help="Schema commands")
    sc_sub = sc.add_subparsers(dest="subcommand")
    sc_init = sc_sub.add_parser("init", help="Initialize schema")
    _add_conn_args(sc_init)
    _add_json_arg(sc_init)
    sc_init.set_defaults(func=cmd_schema_init)
    sc_status = sc_sub.add_parser("status", help="Schema status")
    _add_conn_args(sc_status)
    _add_json_arg(sc_status)
    sc_status.set_defaults(func=cmd_schema_status)

    ar = subs.add_parser("actor-roles", help="Actor role commands")
    ar_sub = ar.add_subparsers(dest="subcommand")
    ar_list = ar_sub.add_parser("list", help="List actor roles")
    ar_list.add_argument("--actor-id", help="Filter by actor_id")
    _add_conn_args(ar_list)
    _add_json_arg(ar_list)
    ar_list.set_defaults(func=cmd_actor_roles_list)

    ver = subs.add_parser("version", help="Show regista version info")
    ver.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON output")
    ver.set_defaults(func=cmd_version)

    doc = subs.add_parser("doctor", help="Health check")
    doc.add_argument(
        "--max-projects",
        type=int,
        default=25,
        help="Upper bound on projects checked individually without --project (default 25)",
    )
    _add_conn_args(doc)
    _add_json_arg(doc)
    doc.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return 2
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help(sys.stderr)
        return 2
    try:
        result: int = func(args)
        return result
    except RegistaError as e:
        return _handle_error(e, json_mode=getattr(args, "json", False))


if __name__ == "__main__":
    sys.exit(main())
