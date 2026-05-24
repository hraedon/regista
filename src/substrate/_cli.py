from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime

import structlog

from substrate import Substrate
from substrate._errors import SubstrateError
from substrate._workflow import validate_yaml as _validate_yaml


class _StderrLoggerFactory:
    def __call__(self, *args):
        return structlog.PrintLogger(file=sys.stderr)


def _configure_structlog_stderr():
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=_StderrLoggerFactory(),
    )


def _resolve_config(args):
    dsn = args.dsn or os.environ.get("SUBSTRATE_DSN")
    project = args.project or os.environ.get("SUBSTRATE_PROJECT")
    hmac_key_path = args.hmac_key_path or os.environ.get("SUBSTRATE_HMAC_KEY_PATH")
    return dsn, project, hmac_key_path


def _require_config(args):
    dsn, project, hmac_key_path = _resolve_config(args)
    missing = []
    if not dsn:
        missing.append("--dsn or SUBSTRATE_DSN")
    if not project:
        missing.append("--project or SUBSTRATE_PROJECT")
    if missing:
        print(f"Missing required config: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)
    return dsn, project, hmac_key_path


def _dump_json(obj):
    if hasattr(obj, "to_dict"):
        data = obj.to_dict()
    elif isinstance(obj, list):
        data = [item.to_dict() if hasattr(item, "to_dict") else item for item in obj]
    elif isinstance(obj, uuid.UUID):
        data = str(obj)
    else:
        data = obj
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


def _handle_error(e: SubstrateError):
    print(f"[{e.code}] {e.message}", file=sys.stderr)
    sys.exit(1)


def _add_common_args(parser):
    parser.add_argument("--dsn", help="Postgres DSN (or SUBSTRATE_DSN)")
    parser.add_argument("--project", help="Project schema name (or SUBSTRATE_PROJECT)")
    parser.add_argument("--hmac-key-path", help="HMAC key file path (or SUBSTRATE_HMAC_KEY_PATH)")
    parser.add_argument("--json", action="store_true", help="JSON output")


def cmd_workflow_validate(args):
    from pathlib import Path
    result = _validate_yaml(Path(args.file))
    if args.json:
        _dump_json(result)
    else:
        if result.valid:
            print(f"Valid: {result.workflow.name} v{result.workflow.version}")
        else:
            for err in result.errors:
                print(f"  {err.path}: {err.message}")
    if not result.valid:
        sys.exit(1)


def cmd_work_item_show(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        wi = sub.get_work_item(uuid.UUID(args.id))
        if wi is None:
            print(f"Work item {args.id!r} not found", file=sys.stderr)
            sys.exit(1)
        if args.json:
            _dump_json(wi)
        else:
            lines = [
                f"WorkItem {wi.work_item_id}",
                f"  workflow: {wi.workflow_name} v{wi.workflow_version}",
                f"  type:     {wi.work_item_type}",
                f"  state:    {wi.current_state}",
                f"  seq:      {wi.last_event_seq}",
                f"  claimed:  {wi.claimed_by or '(none)'}",
            ]
            for line in lines:
                print(line)
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_work_item_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        filters = {}
        if args.workflow:
            filters["workflow_name"] = args.workflow
        if args.state:
            filters["current_states"] = args.state
        if args.type:
            filters["work_item_types"] = args.type
        if args.needs_review:
            filters["needs_review"] = True
        if args.claimable_now:
            filters["claimable_now"] = True
        page = sub.query_work_items(
            **filters,
            page_size=args.page_size,
            cursor=uuid.UUID(args.cursor) if args.cursor else None,
        )
        if args.json:
            _dump_json(page)
        else:
            width = 36
            for item in page.items:
                short_id = str(item.work_item_id)[:8]
                print(
                    f"{short_id:<{width}} "
                    f"{item.workflow_name:20s} "
                    f"{item.current_state:12s} "
                    f"{item.work_item_type}"
                )
            if page.has_more:
                print(f"--cursor={page.cursor}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_events_show(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        evts = sub.read_events(
            work_item_id=uuid.UUID(args.id),
            limit=args.limit,
            before_seq=args.before_seq,
        )
        if args.json:
            _dump_json(evts)
        else:
            for e in evts:
                ts = e.timestamp.isoformat()
                print(f"seq={e.event_seq:<4} {ts}  {e.transition or '(none)'}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_events_tail(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        kw = {"limit": args.limit}
        if args.actor:
            kw["actor_id"] = args.actor
        if args.transition:
            kw["transition"] = args.transition
        if args.since:
            kw["start"] = datetime.fromisoformat(args.since)
        if args.until:
            kw["end"] = datetime.fromisoformat(args.until)
        evts = sub.read_events(**kw)
        if args.json:
            _dump_json(evts)
        else:
            for e in evts:
                ts = e.timestamp.isoformat()
                print(f"{e.work_item_id}  seq={e.event_seq}  {ts}  {e.transition or '(none)'}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_replay(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        report = sub.replay(continue_on_revoked=args.continue_on_revoked)
        if args.json:
            _dump_json(report)
        else:
            print(
                f"ok={report.replayed_ok}  "
                f"drift={report.replayed_drift}  "
                f"halted={report.halted}  "
                f"warnings={report.warnings}"
            )
        if report.replayed_drift > 0 or report.halted > 0:
            sys.exit(1)
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_schema_init(args):
    dsn, project, hmac_key_path = _require_config(args)
    Substrate.create_project(dsn, project, hmac_key_path or "")
    print(f"Schema initialized for project {project!r}")


def cmd_schema_status(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        print(f"substrate_version={sub.substrate_version}")
    finally:
        sub.close()


def cmd_hooks_dead_letter_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        entries = sub.list_dead_lettered_hooks()
        if args.json:
            _dump_json(entries)
        else:
            for e in entries:
                ts = e.dead_lettered_at.isoformat()
                print(f"{e.id}  {e.hook_name:20s}  {ts}  {e.error_message or ''}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_hooks_dead_letter_requeue(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        sub.requeue_dead_lettered_hook(int(args.id))
        print(f"Requeued dead-letter hook {args.id}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_actor_roles_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        roles = sub.list_actor_roles(actor_id=args.actor)
        if args.json:
            _dump_json(roles)
        else:
            for r in roles:
                print(f"{r.actor_id:20s} {r.role:20s} {r.created_at.isoformat()}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        rules = sub.list_recurrence_rules(status=args.status)
        if args.json:
            _dump_json(rules)
        else:
            for r in rules:
                rid = str(r["rule_id"])[:8]
                print(
                    f"{rid}  {r['workflow_name']:20s} "
                    f"{r['schedule_kind']:10s} {r['status']:10s} "
                    f"{r.get('next_fire_at', '')}"
                )
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_due(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        rules = sub.due_recurrences()
        if args.json:
            _dump_json(rules)
        else:
            for r in rules:
                rid = str(r["rule_id"])[:8]
                print(
                    f"{rid}  {r['workflow_name']:20s} "
                    f"next_fire={r.get('next_fire_at', '')}"
                )
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_fire(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        rule, wi = sub.fire_recurrence(uuid.UUID(args.id))
        if args.json:
            _dump_json({"rule": rule, "work_item": wi})
        else:
            rid = str(rule["rule_id"])[:8]
            wi_id = str(wi["work_item_id"])[:8] if wi else "(none)"
            print(f"Fired rule {rid} -> work item {wi_id}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_cancel(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        sub.cancel_recurrence_rule(uuid.UUID(args.id))
        print(f"Cancelled recurrence rule {args.id}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_update(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        updates = {}
        if args.status is not None:
            updates["status"] = args.status
        if args.schedule_expr is not None:
            updates["schedule_expr"] = args.schedule_expr
        if args.template is not None:
            updates["template"] = json.loads(args.template)
        result = sub.update_recurrence_rule(uuid.UUID(args.id), **updates)
        if args.json:
            _dump_json(result)
        else:
            print(f"Updated rule {args.id}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_timestamp_status(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        batches = sub.timestamping.list_batches(status=args.status)
        if args.json:
            _dump_json(batches)
        else:
            for b in batches:
                print(
                    f"{str(b.batch_id)[:8]}  {b.status:10s}  "
                    f"events={len(b.event_ids):>4}  "
                    f"root={b.merkle_root.hex()[:16]}..."
                )
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_timestamp_trigger(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        result = sub.timestamping.trigger()
        if result is None:
            print("No new events to timestamp")
        else:
            print(f"Triggered batch {result.batch_id} with {len(result.event_ids)} events")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_timestamp_verify(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Substrate(dsn, project, hmac_key_path)
    try:
        ok = sub.timestamping.verify_batch(uuid.UUID(args.id))
        print(f"verified={ok}")
    except SubstrateError as e:
        _handle_error(e)
    finally:
        sub.close()


def main(argv=None):
    _configure_structlog_stderr()
    parser = argparse.ArgumentParser(prog="substrate", description="Substrate admin CLI")
    _add_common_args(parser)
    subs = parser.add_subparsers(dest="command")

    # workflow
    wf = subs.add_parser("workflow", help="Workflow commands")
    wf_sub = wf.add_subparsers(dest="subcommand")
    wf_val = wf_sub.add_parser("validate", help="Validate workflow YAML")
    wf_val.add_argument("file", help="Path to YAML file")
    wf_val.add_argument("--json", action="store_true", help="JSON output")

    # work-item
    wi = subs.add_parser("work-item", help="Work item commands")
    wi_sub = wi.add_subparsers(dest="subcommand")
    wi_show = wi_sub.add_parser("show", help="Show a work item")
    wi_show.add_argument("id", help="Work item UUID")
    wi_list = wi_sub.add_parser("list", help="List work items")
    wi_list.add_argument("--workflow", help="Filter by workflow name")
    wi_list.add_argument("--state", action="append", help="Filter by state")
    wi_list.add_argument("--type", action="append", help="Filter by work item type")
    wi_list.add_argument("--needs-review", action="store_true", help="Filter needs review")
    wi_list.add_argument("--claimable-now", action="store_true", help="Filter claimable now")
    wi_list.add_argument("--page-size", type=int, default=100)
    wi_list.add_argument("--cursor", help="Pagination cursor")

    # events
    ev = subs.add_parser("events", help="Event commands")
    ev_sub = ev.add_subparsers(dest="subcommand")
    ev_show = ev_sub.add_parser("show", help="Show events for a work item")
    ev_show.add_argument("id", help="Work item UUID")
    ev_show.add_argument("--limit", type=int, default=100)
    ev_show.add_argument("--before-seq", type=int, default=None)
    ev_tail = ev_sub.add_parser("tail", help="Tail events across items")
    ev_tail.add_argument("--actor", help="Filter by actor_id")
    ev_tail.add_argument("--transition", help="Filter by transition name")
    ev_tail.add_argument("--since", help="ISO 8601 start timestamp")
    ev_tail.add_argument("--until", help="ISO 8601 end timestamp")
    ev_tail.add_argument("--limit", type=int, default=100)

    # replay
    rep = subs.add_parser("replay", help="Run replay drift check")
    rep.add_argument("--continue-on-revoked", action="store_true", help="Skip revoked-key events")

    # schema
    sc = subs.add_parser("schema", help="Schema commands")
    sc_sub = sc.add_subparsers(dest="subcommand")
    sc_sub.add_parser("init", help="Initialize schema")
    sc_sub.add_parser("status", help="Schema status")

    # hooks
    hk = subs.add_parser("hooks", help="Hook commands")
    hk_sub = hk.add_subparsers(dest="subcommand")
    hk_dl = hk_sub.add_parser("dead-letter", help="Dead-letter commands")
    hk_dl_sub = hk_dl.add_subparsers(dest="dl_command")
    hk_dl_sub.add_parser("list", help="List dead-lettered hooks")
    requeue = hk_dl_sub.add_parser("requeue", help="Requeue a dead-lettered hook")
    requeue.add_argument("id", help="Dead-letter entry ID")

    # actor-roles
    ar = subs.add_parser("actor-roles", help="Actor role commands")
    ar_sub = ar.add_subparsers(dest="subcommand")
    ar_list = ar_sub.add_parser("list", help="List actor roles")
    ar_list.add_argument("--actor", help="Filter by actor_id")

    # recurrence
    rc = subs.add_parser("recurrence", help="Recurrence rule commands")
    rc_sub = rc.add_subparsers(dest="subcommand")
    rc_list = rc_sub.add_parser("list", help="List recurrence rules")
    rc_list.add_argument("--status", help="Filter by status (active/cancelled/exhausted)")
    rc_sub.add_parser("due", help="Show due recurrence rules")
    rc_fire = rc_sub.add_parser("fire", help="Fire a due recurrence rule")
    rc_fire.add_argument("id", help="Rule UUID")
    rc_cancel = rc_sub.add_parser("cancel", help="Cancel a recurrence rule")
    rc_cancel.add_argument("id", help="Rule UUID")
    rc_update = rc_sub.add_parser("update", help="Update a recurrence rule")
    rc_update.add_argument("id", help="Rule UUID")
    rc_update.add_argument("--status", help="New status")
    rc_update.add_argument("--schedule-expr", help="New schedule expression")
    rc_update.add_argument("--template", help="New template (JSON string)")

    # timestamp
    ts = subs.add_parser("timestamp", help="Timestamping commands")
    ts_sub = ts.add_subparsers(dest="subcommand")
    ts_sub.add_parser("status", help="List timestamp batches")
    ts_sub.add_parser("trigger", help="Trigger a new timestamp batch")
    ts_verify = ts_sub.add_parser("verify", help="Verify a timestamp batch")
    ts_verify.add_argument("id", help="Batch UUID")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(2)

    if args.command == "workflow" and args.subcommand == "validate":
        cmd_workflow_validate(args)
    elif args.command == "work-item" and args.subcommand == "show":
        cmd_work_item_show(args)
    elif args.command == "work-item" and args.subcommand == "list":
        cmd_work_item_list(args)
    elif args.command == "events" and args.subcommand == "show":
        cmd_events_show(args)
    elif args.command == "events" and args.subcommand == "tail":
        cmd_events_tail(args)
    elif args.command == "replay":
        cmd_replay(args)
    elif args.command == "schema" and args.subcommand == "init":
        cmd_schema_init(args)
    elif args.command == "schema" and args.subcommand == "status":
        cmd_schema_status(args)
    elif args.command == "hooks" and args.subcommand == "dead-letter":
        if args.dl_command == "list":
            cmd_hooks_dead_letter_list(args)
        elif args.dl_command == "requeue":
            cmd_hooks_dead_letter_requeue(args)
        else:
            hk_dl.print_help()
            sys.exit(2)
    elif args.command == "actor-roles" and args.subcommand == "list":
        cmd_actor_roles_list(args)
    elif args.command == "timestamp":
        if args.subcommand == "status":
            cmd_timestamp_status(args)
        elif args.subcommand == "trigger":
            cmd_timestamp_trigger(args)
        elif args.subcommand == "verify":
            cmd_timestamp_verify(args)
        else:
            ts.print_help()
            sys.exit(2)
    elif args.command == "recurrence" and args.subcommand == "list":
        cmd_recurrence_list(args)
    elif args.command == "recurrence" and args.subcommand == "due":
        cmd_recurrence_due(args)
    elif args.command == "recurrence" and args.subcommand == "fire":
        cmd_recurrence_fire(args)
    elif args.command == "recurrence" and args.subcommand == "cancel":
        cmd_recurrence_cancel(args)
    elif args.command == "recurrence" and args.subcommand == "update":
        cmd_recurrence_update(args)
    else:
        target = subs.choices.get(args.command)
        if target:
            target.print_help()
        else:
            parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
