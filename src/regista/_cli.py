from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime

import structlog

from regista import Regista
from regista._errors import RegistaError
from regista._workflow import validate_yaml as _validate_yaml


class _StderrLoggerFactory:
    def __call__(self, *args):
        return structlog.PrintLogger(file=sys.stderr)


def _configure_structlog_stderr():
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=_StderrLoggerFactory(),
    )


def _resolve_config(args):
    dsn = args.dsn or os.environ.get("REGISTA_DSN")
    project = args.project or os.environ.get("REGISTA_PROJECT")
    hmac_key_path = args.hmac_key_path or os.environ.get("REGISTA_HMAC_KEY_PATH")
    return dsn, project, hmac_key_path


def _require_config(args):
    dsn, project, hmac_key_path = _resolve_config(args)
    missing = []
    if not dsn:
        missing.append("--dsn or REGISTA_DSN")
    if not project:
        missing.append("--project or REGISTA_PROJECT")
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


def _handle_error(e: RegistaError):
    print(f"[{e.code}] {e.message}", file=sys.stderr)
    sys.exit(1)


def _add_common_args(parser):
    parser.add_argument("--dsn", help="Postgres DSN (or REGISTA_DSN)")
    parser.add_argument("--project", help="Project schema name (or REGISTA_PROJECT)")
    parser.add_argument("--hmac-key-path", help="HMAC key file path (or REGISTA_HMAC_KEY_PATH)")
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
    sub = Regista(dsn, project, hmac_key_path)
    try:
        work_item_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid work item ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    try:
        wi = sub.get_work_item(work_item_id)
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
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_work_item_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        cursor_uuid = None
        if args.cursor:
            try:
                cursor_uuid = uuid.UUID(args.cursor)
            except ValueError:
                print(f"Invalid cursor UUID: {args.cursor!r}", file=sys.stderr)
                sys.exit(1)
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
            cursor=cursor_uuid,
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
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_events_show(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        work_item_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid work item ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    try:
        evts = sub.read_events(
            work_item_id=work_item_id,
            limit=args.limit,
            before_seq=args.before_seq,
        )
        if args.json:
            _dump_json(evts)
        else:
            for e in evts:
                ts = e.timestamp.isoformat()
                print(f"seq={e.event_seq:<4} {ts}  {e.transition or '(none)'}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_events_tail(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        kw = {"limit": args.limit}
        if args.actor:
            kw["actor_id"] = args.actor
        if args.transition:
            kw["transition"] = args.transition
        if args.since:
            try:
                kw["start"] = datetime.fromisoformat(args.since)
            except ValueError:
                print(f"Invalid --since datetime: {args.since!r}", file=sys.stderr)
                sys.exit(1)
        if args.until:
            try:
                kw["end"] = datetime.fromisoformat(args.until)
            except ValueError:
                print(f"Invalid --until datetime: {args.until!r}", file=sys.stderr)
                sys.exit(1)
        evts = sub.read_events(**kw)
        if args.json:
            _dump_json(evts)
        else:
            for e in evts:
                ts = e.timestamp.isoformat()
                print(f"{e.work_item_id}  seq={e.event_seq}  {ts}  {e.transition or '(none)'}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_replay(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
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
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_schema_init(args):
    dsn, project, hmac_key_path = _require_config(args)
    Regista.create_project(dsn, project, hmac_key_path or "")
    print(f"Schema initialized for project {project!r}")


def cmd_schema_status(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        print(f"regista_version={sub.regista_version}")
    finally:
        sub.close()


def cmd_hooks_dead_letter_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        entries = sub.list_dead_lettered_hooks()
        if args.json:
            _dump_json(entries)
        else:
            for e in entries:
                ts = e.dead_lettered_at.isoformat()
                print(f"{e.id}  {e.hook_name:20s}  {ts}  {e.error_message or ''}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_hooks_dead_letter_requeue(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        entry_id = int(args.id)
    except ValueError:
        print(f"Invalid dead-letter hook ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    try:
        sub.requeue_dead_lettered_hook(entry_id)
        print(f"Requeued dead-letter hook {args.id}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_actor_roles_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        roles = sub.list_actor_roles(actor_id=args.actor)
        if args.json:
            _dump_json(roles)
        else:
            for r in roles:
                print(f"{r.actor_id:20s} {r.role:20s} {r.created_at.isoformat()}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
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
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_due(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
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
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_fire(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        rule_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid rule ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    try:
        rule, wi = sub.fire_recurrence(rule_id)
        if args.json:
            _dump_json({"rule": rule, "work_item": wi})
        else:
            rid = str(rule["rule_id"])[:8]
            wi_id = str(wi["work_item_id"])[:8] if wi else "(none)"
            print(f"Fired rule {rid} -> work item {wi_id}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_cancel(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        rule_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid rule ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    try:
        sub.cancel_recurrence_rule(rule_id)
        print(f"Cancelled recurrence rule {args.id}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_recurrence_update(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        rule_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid rule ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    try:
        updates = {}
        if args.status is not None:
            updates["status"] = args.status
        if args.schedule_expr is not None:
            updates["schedule_expr"] = args.schedule_expr
        if args.template is not None:
            updates["template"] = json.loads(args.template)
        result = sub.update_recurrence_rule(rule_id, **updates)
        if args.json:
            _dump_json(result)
        else:
            print(f"Updated rule {args.id}")
    except RegistaError as e:
        _handle_error(e)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in --template: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sub.close()


def cmd_timestamp_status(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
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
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_timestamp_trigger(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        result = sub.timestamping.trigger()
        if result is None:
            print("No new events to timestamp")
        else:
            print(f"Triggered batch {result.batch_id} with {len(result.event_ids)} events")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_timestamp_verify(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        batch_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid batch ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    try:
        ok = sub.timestamping.verify_batch(batch_id)
        print(f"verified={ok}")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_witness_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        result = sub.list_witnesses(status=args.__dict__.get("status"))
        if not result:
            print("No witnesses registered.")
            return
        for w in result:
            print(
                f"  {w['witness_id'][:8]}...  {w['url'][:50]:<50}  "
                f"{w['status']:<8}  failures={w.get('consecutive_failures', 0)}"
            )
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_witness_deliver(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        count = sub.deliver_pending_witness_receipts()
        print(f"Delivered {count} receipt(s).")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_witness_receipts(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        evt_id = witness_id = None
        if args.event_id:
            try:
                evt_id = uuid.UUID(args.event_id)
            except ValueError:
                print(f"Invalid event ID: {args.event_id!r}", file=sys.stderr)
                sys.exit(1)
        if args.witness_id:
            try:
                witness_id = uuid.UUID(args.witness_id)
            except ValueError:
                print(f"Invalid witness ID: {args.witness_id!r}", file=sys.stderr)
                sys.exit(1)
        result = sub.list_witness_receipts(
            event_id=evt_id,
            witness_id=witness_id,
            status=args.status,
            limit=args.limit,
        )
        if not result:
            print("No receipts found.")
            return
        for r in result:
            print(
                f"  {r['receipt_id'][:8]}...  witness={r['witness_id'][:8]}...  "
                f"event={r['event_id'][:8]}...  status={r['status']}"
            )
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_events_archive(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        ts = datetime.fromisoformat(args.before)
    except ValueError:
        print(f"Invalid timestamp: {args.before!r}", file=sys.stderr)
        sys.exit(1)
    try:
        count = sub.archive_events(before_timestamp=ts, dry_run=args.dry_run)
        if args.dry_run:
            print(f"Would archive {count} event(s).")
        else:
            print(f"Archived {count} event(s).")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_workflow_compose(args):
    from regista._workflow_compose import compose_workflow as _compose

    try:
        composed, source_map = _compose(args.file)
        if args.json:
            _dump_json({"composed": composed, "source_map": source_map})
        else:
            print(f"Composed workflow: {composed.get('name', '?')} v{composed.get('version', '?')}")
            for source in source_map.get("sources", []):
                print(f"  included: {source}")
    except RegistaError as e:
        _handle_error(e)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _print_help_and_exit(parser, code=2):
    parser.print_help()
    sys.exit(code)


def cmd_work_item_create(args):
    dsn, project, hmac_key_path = _require_config(args)
    custom_fields = None
    if args.custom_fields:
        try:
            custom_fields = json.loads(args.custom_fields)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON for --custom-fields: {e}", file=sys.stderr)
            sys.exit(1)
    not_before = None
    if args.not_before:
        try:
            not_before = datetime.fromisoformat(args.not_before)
        except ValueError:
            print(f"Invalid timestamp: {args.not_before!r}", file=sys.stderr)
            sys.exit(1)
    if not args.confirm:
        print("Would create work item:")
        print(f"  workflow:  {args.workflow}")
        print(f"  type:      {args.type}")
        print(f"  actor:     {args.actor_id}")
        if custom_fields:
            print(f"  fields:    {json.dumps(custom_fields)}")
        print("\nRun with --confirm to execute.")
        return
    sub = Regista(dsn, project, hmac_key_path)
    try:
        wi, evt = sub.create_work_item(
            workflow_name=args.workflow,
            work_item_type=args.type,
            actor_id=args.actor_id,
            custom_fields=custom_fields,
            not_before=not_before,
        )
        print(f"Created {wi.work_item_id}")
        if args.json:
            _dump_json({"work_item": wi, "event": evt})
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_work_item_transition(args):
    dsn, project, hmac_key_path = _require_config(args)
    try:
        work_item_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid work item ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    payload = None
    if args.payload:
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON for --payload: {e}", file=sys.stderr)
            sys.exit(1)
    custom_fields = None
    if args.custom_fields:
        try:
            custom_fields = json.loads(args.custom_fields)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON for --custom-fields: {e}", file=sys.stderr)
            sys.exit(1)
    actor_metadata = None
    if args.actor_metadata:
        try:
            actor_metadata = json.loads(args.actor_metadata)
        except json.JSONDecodeError as e:
            print(f"Invalid JSON for --actor-metadata: {e}", file=sys.stderr)
            sys.exit(1)
    if not args.confirm:
        print(f"Would transition work item {args.id[:8]}...")
        print(f"  transition:  {args.transition}")
        print(f"  actor:       {args.actor_id}")
        if payload:
            print(f"  payload:     {json.dumps(payload)}")
        if custom_fields:
            print(f"  fields:      {json.dumps(custom_fields)}")
        print("\nRun with --confirm to execute.")
        return
    sub = Regista(dsn, project, hmac_key_path)
    try:
        evt = sub.transition(
            work_item_id=work_item_id,
            transition_name=args.transition,
            actor_id=args.actor_id,
            actor_metadata=actor_metadata,
            payload=payload,
            custom_fields=custom_fields,
        )
        print(f"Transitioned: seq={evt.event_seq}")
        if args.json:
            _dump_json(evt)
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_webhook_register(args):
    dsn, project, hmac_key_path = _require_config(args)
    transitions = args.transitions.split(",") if args.transitions else None
    workflows = args.workflows.split(",") if args.workflows else None
    if not args.confirm:
        print("Would register webhook:")
        print(f"  url:          {args.url}")
        if transitions:
            print(f"  transitions:  {transitions}")
        if workflows:
            print(f"  workflows:    {workflows}")
        print("\nRun with --confirm to execute.")
        return
    sub = Regista(dsn, project, hmac_key_path)
    try:
        result = sub.register_webhook(
            url=args.url,
            transitions=transitions,
            workflows=workflows,
        )
        print(f"Registered webhook {result['webhook_id']}")
        if args.json:
            _dump_json(result)
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_webhook_list(args):
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        result = sub.list_webhooks(status=args.__dict__.get("status"))
        if not result:
            print("No webhooks registered.")
            return
        for w in result:
            print(
                f"  {str(w['webhook_id'])[:8]}...  {w['url'][:50]:<50}  "
                f"{w['status']}"
            )
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def cmd_webhook_remove(args):
    dsn, project, hmac_key_path = _require_config(args)
    try:
        webhook_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid webhook ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        sub.unregister_webhook(webhook_id)
        print(f"Removed webhook {args.id[:8]}...")
    except RegistaError as e:
        _handle_error(e)
    finally:
        sub.close()


def main(argv=None):
    _configure_structlog_stderr()
    parser = argparse.ArgumentParser(prog="regista", description="Regista admin CLI")
    _add_common_args(parser)
    subs = parser.add_subparsers(dest="command")

    # workflow
    wf = subs.add_parser("workflow", help="Workflow commands")
    wf_sub = wf.add_subparsers(dest="subcommand")
    wf_val = wf_sub.add_parser("validate", help="Validate workflow YAML")
    wf_val.add_argument("file", help="Path to YAML file")
    wf_val.add_argument("--json", action="store_true", help="JSON output")
    wf_val.set_defaults(func=cmd_workflow_validate)

    # work-item
    wi = subs.add_parser("work-item", help="Work item commands")
    wi_sub = wi.add_subparsers(dest="subcommand")
    wi_show = wi_sub.add_parser("show", help="Show a work item")
    wi_show.add_argument("id", help="Work item UUID")
    wi_show.set_defaults(func=cmd_work_item_show)
    wi_list = wi_sub.add_parser("list", help="List work items")
    wi_list.add_argument("--workflow", help="Filter by workflow name")
    wi_list.add_argument("--state", action="append", help="Filter by state")
    wi_list.add_argument("--type", action="append", help="Filter by work item type")
    wi_list.add_argument("--needs-review", action="store_true", help="Filter needs review")
    wi_list.add_argument("--claimable-now", action="store_true", help="Filter claimable now")
    wi_list.add_argument("--page-size", type=int, default=100)
    wi_list.add_argument("--cursor", help="Pagination cursor")
    wi_list.set_defaults(func=cmd_work_item_list)

    # events
    ev = subs.add_parser("events", help="Event commands")
    ev_sub = ev.add_subparsers(dest="subcommand")
    ev_show = ev_sub.add_parser("show", help="Show events for a work item")
    ev_show.add_argument("id", help="Work item UUID")
    ev_show.add_argument("--limit", type=int, default=100)
    ev_show.add_argument("--before-seq", type=int, default=None)
    ev_show.set_defaults(func=cmd_events_show)
    ev_tail = ev_sub.add_parser("tail", help="Tail events across items")
    ev_tail.add_argument("--actor", help="Filter by actor_id")
    ev_tail.add_argument("--transition", help="Filter by transition name")
    ev_tail.add_argument("--since", help="ISO 8601 start timestamp")
    ev_tail.add_argument("--until", help="ISO 8601 end timestamp")
    ev_tail.add_argument("--limit", type=int, default=100)
    ev_tail.set_defaults(func=cmd_events_tail)
    ev_archive = ev_sub.add_parser("archive", help="Archive old events")
    ev_archive.add_argument("--before", required=True, help="ISO 8601 timestamp")
    ev_archive.add_argument("--dry-run", action="store_true", help="Count without archiving")
    ev_archive.set_defaults(func=cmd_events_archive)

    # replay
    rep = subs.add_parser("replay", help="Run replay drift check")
    rep.add_argument("--continue-on-revoked", action="store_true", help="Skip revoked-key events")
    rep.set_defaults(func=cmd_replay)

    # schema
    sc = subs.add_parser("schema", help="Schema commands")
    sc_sub = sc.add_subparsers(dest="subcommand")
    sc_sub.add_parser("init", help="Initialize schema").set_defaults(func=cmd_schema_init)
    sc_sub.add_parser("status", help="Schema status").set_defaults(func=cmd_schema_status)

    # hooks
    hk = subs.add_parser("hooks", help="Hook commands")
    hk_sub = hk.add_subparsers(dest="subcommand")
    hk_dl = hk_sub.add_parser("dead-letter", help="Dead-letter commands")
    hk_dl_sub = hk_dl.add_subparsers(dest="dl_command")
    hk_dl_list = hk_dl_sub.add_parser("list", help="List dead-lettered hooks")
    hk_dl_list.set_defaults(func=cmd_hooks_dead_letter_list)
    requeue = hk_dl_sub.add_parser("requeue", help="Requeue a dead-lettered hook")
    requeue.add_argument("id", help="Dead-letter entry ID")
    requeue.set_defaults(func=cmd_hooks_dead_letter_requeue)

    # actor-roles
    ar = subs.add_parser("actor-roles", help="Actor role commands")
    ar_sub = ar.add_subparsers(dest="subcommand")
    ar_list = ar_sub.add_parser("list", help="List actor roles")
    ar_list.add_argument("--actor", help="Filter by actor_id")
    ar_list.set_defaults(func=cmd_actor_roles_list)

    # recurrence
    rc = subs.add_parser("recurrence", help="Recurrence rule commands")
    rc_sub = rc.add_subparsers(dest="subcommand")
    rc_list = rc_sub.add_parser("list", help="List recurrence rules")
    rc_list.add_argument("--status", help="Filter by status (active/cancelled/exhausted)")
    rc_list.set_defaults(func=cmd_recurrence_list)
    rc_sub.add_parser("due", help="Show due recurrence rules").set_defaults(func=cmd_recurrence_due)
    rc_fire = rc_sub.add_parser("fire", help="Fire a due recurrence rule")
    rc_fire.add_argument("id", help="Rule UUID")
    rc_fire.set_defaults(func=cmd_recurrence_fire)
    rc_cancel = rc_sub.add_parser("cancel", help="Cancel a recurrence rule")
    rc_cancel.add_argument("id", help="Rule UUID")
    rc_cancel.set_defaults(func=cmd_recurrence_cancel)
    rc_update = rc_sub.add_parser("update", help="Update a recurrence rule")
    rc_update.add_argument("id", help="Rule UUID")
    rc_update.add_argument("--status", help="New status")
    rc_update.add_argument("--schedule-expr", help="New schedule expression")
    rc_update.add_argument("--template", help="New template (JSON string)")
    rc_update.set_defaults(func=cmd_recurrence_update)

    # timestamp
    ts = subs.add_parser("timestamp", help="Timestamping commands")
    ts_sub = ts.add_subparsers(dest="subcommand")
    ts_status = ts_sub.add_parser("status", help="List timestamp batches")
    ts_status.set_defaults(func=cmd_timestamp_status)
    ts_trigger = ts_sub.add_parser("trigger", help="Trigger a new timestamp batch")
    ts_trigger.set_defaults(func=cmd_timestamp_trigger)
    ts_verify = ts_sub.add_parser("verify", help="Verify a timestamp batch")
    ts_verify.add_argument("id", help="Batch UUID")
    ts_verify.set_defaults(func=cmd_timestamp_verify)

    # witness
    wt = subs.add_parser("witness", help="Witness commands")
    wt_sub = wt.add_subparsers(dest="subcommand")
    wt_list = wt_sub.add_parser("list", help="List witness registrations")
    wt_list.add_argument("--status", help="Filter by status (active/paused/failed)")
    wt_list.set_defaults(func=cmd_witness_list)
    wt_deliver = wt_sub.add_parser("deliver", help="Deliver pending witness receipts")
    wt_deliver.set_defaults(func=cmd_witness_deliver)
    wt_receipts = wt_sub.add_parser("receipts", help="List witness receipts")
    wt_receipts.add_argument("--event-id", help="Filter by event UUID")
    wt_receipts.add_argument("--witness-id", help="Filter by witness UUID")
    wt_receipts.add_argument("--status", help="Filter by receipt status")
    wt_receipts.add_argument("--limit", type=int, default=100)
    wt_receipts.set_defaults(func=cmd_witness_receipts)

    # workflow compose
    wf_compose = wf_sub.add_parser("compose", help="Compose workflow with extends")
    wf_compose.add_argument("file", help="Path to YAML file")
    wf_compose.add_argument("--json", action="store_true", help="JSON output")
    wf_compose.set_defaults(func=cmd_workflow_compose)

    # work-item create
    wi_create = wi_sub.add_parser("create", help="Create a work item")
    wi_create.add_argument("--workflow", required=True, help="Workflow name")
    wi_create.add_argument("--type", required=True, help="Work item type")
    wi_create.add_argument("--actor-id", required=True, help="Actor ID")
    wi_create.add_argument("--custom-fields", help="Custom fields (JSON)")
    wi_create.add_argument("--not-before", help="ISO 8601 timestamp")
    wi_create.add_argument("--confirm", action="store_true", help="Execute the action")
    wi_create.set_defaults(func=cmd_work_item_create)

    # work-item transition
    wi_trans = wi_sub.add_parser("transition", help="Transition a work item")
    wi_trans.add_argument("id", help="Work item UUID")
    wi_trans.add_argument("--transition", required=True, help="Transition name")
    wi_trans.add_argument("--actor-id", required=True, help="Actor ID")
    wi_trans.add_argument("--actor-metadata", help="Actor metadata (JSON)")
    wi_trans.add_argument("--payload", help="Transition payload (JSON)")
    wi_trans.add_argument("--custom-fields", help="Custom fields update (JSON)")
    wi_trans.add_argument("--confirm", action="store_true", help="Execute the action")
    wi_trans.set_defaults(func=cmd_work_item_transition)

    # webhook
    wh = subs.add_parser("webhook", help="Webhook commands")
    wh_sub = wh.add_subparsers(dest="subcommand")
    wh_reg = wh_sub.add_parser("register", help="Register a webhook")
    wh_reg.add_argument("--url", required=True, help="Webhook URL")
    wh_reg.add_argument("--transitions", help="Comma-separated transition names")
    wh_reg.add_argument("--workflows", help="Comma-separated workflow names")
    wh_reg.add_argument("--confirm", action="store_true", help="Execute the action")
    wh_reg.set_defaults(func=cmd_webhook_register)
    wh_list = wh_sub.add_parser("list", help="List webhooks")
    wh_list.add_argument("--status", help="Filter by status")
    wh_list.set_defaults(func=cmd_webhook_list)
    wh_rm = wh_sub.add_parser("remove", help="Remove a webhook")
    wh_rm.add_argument("id", help="Webhook UUID")
    wh_rm.set_defaults(func=cmd_webhook_remove)

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(2)

    if hasattr(args, "func"):
        args.func(args)
    else:
        target = subs.choices.get(args.command)
        if target:
            target.print_help()
        else:
            parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
