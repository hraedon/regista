from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, NoReturn

import structlog

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._workflow import validate_yaml as _validate_yaml


class _StderrLoggerFactory:
    def __call__(self, *args: Any) -> Any:
        return structlog.PrintLogger(file=sys.stderr)


def _configure_structlog_stderr() -> None:
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=_StderrLoggerFactory(),
    )


def _resolve_config(args: argparse.Namespace) -> tuple[str | None, str | None, str | None]:
    dsn = args.dsn or os.environ.get("REGISTA_DSN")
    project = args.project or os.environ.get("REGISTA_PROJECT")
    # REGISTA_KEY_PATH is the canonical name (_config.CANONICAL_VARS);
    # REGISTA_HMAC_KEY_PATH is its legacy alias. Reading only the alias here is
    # why `principal enroll`, `replay` and `principal list` ignored the variable
    # every runbook and suite.env actually sets, while `doctor` — which goes
    # through _config.resolve — honoured it (WI-229c, WI-225).
    hmac_key_path = (
        args.hmac_key_path
        or os.environ.get("REGISTA_KEY_PATH")
        or os.environ.get("REGISTA_HMAC_KEY_PATH")
    )
    return dsn, project, hmac_key_path


def _require_config(args: argparse.Namespace) -> tuple[str, str, str | None]:
    dsn, project, hmac_key_path = _resolve_config(args)
    missing = []
    if not dsn:
        missing.append("--dsn or REGISTA_DSN")
    if not project:
        missing.append("--project or REGISTA_PROJECT")
    if missing:
        print(f"Missing required config: {', '.join(missing)}", file=sys.stderr)
        sys.exit(2)
    assert dsn is not None
    assert project is not None
    return dsn, project, hmac_key_path


def _dump_json(obj: Any) -> None:
    if hasattr(obj, "to_dict"):
        data = obj.to_dict()
    elif isinstance(obj, list):
        data = [item.to_dict() if hasattr(item, "to_dict") else item for item in obj]
    elif isinstance(obj, uuid.UUID):
        data = str(obj)
    else:
        data = obj
    print(json.dumps(data, indent=2, sort_keys=True, default=str))


# Transient failures a caller may reasonably retry (suite CLI contract v1
# §3); everything else is a caller error until proven otherwise.
_RETRYABLE_CODES = frozenset(
    {
        "CLAIM_CONTESTED",
        "CONCURRENT_MODIFICATION",
    }
)


def _error_envelope(e: RegistaError) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": str(e.code),
            "message": e.message,
            "detail": (
                None
                if e.detail is None
                else json.dumps(e.detail, sort_keys=True, default=str)
            ),
            "retryable": str(e.code) in _RETRYABLE_CODES,
            "partial": None,
        },
    }


def _handle_error(e: RegistaError, json_mode: bool = False) -> NoReturn:
    """Report a RegistaError per the suite CLI contract v1 and exit 1.

    Under --json the common error envelope is the single stdout document
    (contract §3 — consumers get one parse path for both outcomes), *and* a
    one-line human diagnostic goes to stderr. The envelope stays on stdout
    because that is where the contract puts it; the stderr line exists because a
    downstream stderr-only parser otherwise sees nothing at all on a refusal
    (WI-229). Contract §1 permits diagnostics on stderr in either mode.

    Either way exit is nonzero — no path prints an error and exits 0.
    """
    if json_mode:
        print(json.dumps(_error_envelope(e), indent=2))
    print(f"[{e.code}] {e.message}", file=sys.stderr)
    sys.exit(1)


def _fail_json(payload: Any, *, json_mode: bool, diagnostic: str) -> NoReturn:
    """Emit a verb's own failure document and exit 1 (contract §2).

    For verbs whose failure is reported inside their *own* result shape (a
    ``provision`` record with an ``error``, a ``verify`` report with
    ``verified: false``) rather than as an error envelope. The machine-readable
    channel keeps carrying the machine-readable answer; the exit code stops
    saying the opposite of the body.
    """
    if json_mode:
        _dump_json(payload)
    print(diagnostic, file=sys.stderr)
    sys.exit(1)


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dsn", help="Postgres DSN (or REGISTA_DSN)")
    parser.add_argument("--project", help="Project schema name (or REGISTA_PROJECT)")
    parser.add_argument("--hmac-key-path", help="HMAC key file path (or REGISTA_HMAC_KEY_PATH)")
    parser.add_argument("--json", action="store_true", help="JSON output")


def cmd_workflow_validate(args: argparse.Namespace) -> None:
    from pathlib import Path

    source = Path(args.file)
    if not source.is_file():
        # Contract §5: a missing input is a documented error (envelope +
        # exit 1), never an uncaught FileNotFoundError traceback.
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"workflow file not found: {args.file}",
        )
    result = _validate_yaml(source)
    if args.json:
        _dump_json(result)
    else:
        if result.valid:
            assert result.workflow is not None
            print(f"Valid: {result.workflow.name} v{result.workflow.version}")
        else:
            for err in result.errors:
                print(f"  {err.path}: {err.message}")
    if not result.valid:
        sys.exit(1)


def cmd_work_item_show(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_work_item_list(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_events_show(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_events_tail(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_replay(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path, read_only=args.read_only)
    try:
        # WI-223: the binding check is on by default. Printing
        # principal_binding_failures=0 for a run that never looked is an
        # affirmative claim the chain was attributable when nothing checked.
        report = sub.replay(
            continue_on_revoked=args.continue_on_revoked,
            verify_principal_binding=not args.no_verify_principal_binding,
        )
        if args.json:
            _dump_json(report)
        else:
            if report.principal_binding_verified:
                binding = f"principal_binding_failures={report.principal_binding_failures}"
            else:
                binding = "principal_binding=not-verified"
            print(
                f"ok={report.replayed_ok}  "
                f"drift={report.replayed_drift}  "
                f"halted={report.halted}  "
                f"warnings={report.warnings}  "
                f"unverifiable={report.unverifiable}  "
                f"{binding}"
            )
            # WI-266: chain breaks are a structural tampering verdict, not an
            # advisory — print them on their own line so a scripted reader
            # cannot mistake them for part of the advisory summary.
            if report.chain_breaks > 0:
                print(f"chain_breaks={report.chain_breaks}")
            if report.unverifiable > 0:
                # WI-267: distinct from BOTH `warnings` and `chain_breaks`.
                # A chain break is a detected tamper and exits non-zero below;
                # this says part of the log was replayed with NO cryptographic
                # check at all. Nothing failed — nothing was checked. That is
                # an evidentiary gap, so it is reported loudly and does not by
                # itself fail the exit status.
                print(
                    f"note: {report.unverifiable} event(s) could not be "
                    "verified (no stored envelope, no resolvable key, or "
                    "never signed). Nothing failed — nothing was checked. "
                    "Grep the log for replay.event_envelope_absent / "
                    "replay.event_unverifiable / "
                    "replay.keyless_no_signatures_verified.",
                    file=sys.stderr,
                )
        if (
            report.replayed_drift > 0
            or report.halted > 0
            or report.chain_breaks > 0
        ):
            sys.exit(1)
        if args.strict_principal_binding and report.principal_binding_failures > 0:
            sys.exit(1)
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_schema_init(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    Regista.create_project(dsn, project, hmac_key_path or "")
    print(f"Schema initialized for project {project!r}")


def cmd_schema_status(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        print(f"regista_version={sub.regista_version}")
    finally:
        sub.close()


def cmd_schema_repair_checksums(args: argparse.Namespace) -> None:
    dsn, project, _ = _require_config(args)
    from regista._connection import ConnectionManager
    from regista._migrations import repair_checksums

    mgr = ConnectionManager(dsn, project)
    try:
        mgr.open()
        repaired = repair_checksums(mgr)
        if repaired:
            print(f"Repaired checksums for migrations: {repaired}")
        else:
            print("No checksum drift detected")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        mgr.close()


def cmd_hooks_dead_letter_list(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_hooks_dead_letter_requeue(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_actor_roles_list(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_recurrence_list(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_recurrence_due(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        rules = sub.due_recurrences()
        if args.json:
            _dump_json(rules)
        else:
            for r in rules:
                rid = str(r["rule_id"])[:8]
                print(f"{rid}  {r['workflow_name']:20s} next_fire={r.get('next_fire_at', '')}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_recurrence_fire(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_recurrence_cancel(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_recurrence_update(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    except json.JSONDecodeError as e:
        print(f"Invalid JSON in --template: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        sub.close()


def cmd_witness_list(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_witness_deliver(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        count = sub.deliver_pending_witness_receipts()
        print(f"Delivered {count} receipt(s).")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_witness_receipts(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_events_archive(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_bundle_export(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        result = sub.export_audit_bundle(
            args.output,
            since_seq=args.since_seq,
            until_seq=args.until_seq,
        )
        sv = result["self_verification"]
        if getattr(args, "json", False):
            _dump_json(result)
        else:
            print(f"Bundle exported to {result['output_path']}")
            print(f"  events:           {result['event_count']}")
            print(f"  public_keys:      {result['public_key_count']}")
            print(f"  bundle_hash:      {result['bundle_hash']}")
            print(f"  bundle_bytes:     {result['bundle_bytes']}")
            print(
                f"  self_verified:    {'yes' if sv['verified'] else 'NO'} "
                f"(signatures {sv['signatures_verified']} verified, "
                f"{sv['signatures_unverifiable']} unverifiable, "
                f"check {sv['signature_check']})"
            )
        if not sv["verified"]:
            print(
                "warning: the artifact was written but preserves evidence "
                "the offline verifier rejects — run `bundle verify` for the "
                "full report:",
                file=sys.stderr,
            )
            if result["event_count"] > 0 and sv["signatures_verified"] == 0:
                print(
                    "  - no event signature could be verified offline "
                    f"({sv['signatures_unverifiable']} unverifiable). An HMAC "
                    "store cannot produce an offline-authenticated bundle: the "
                    "secret is deliberately never exported. Re-export from an "
                    "asymmetric (ed25519) store, or pass --allow-unverified to "
                    "accept an internally-consistent-only artifact.",
                    file=sys.stderr,
                )
            for err in sv["errors"]:
                print(f"  - {err}", file=sys.stderr)
            # Exit codes are the API pipelines read (the WI-240 complaint):
            # 0 must mean "exported AND verifiable". Archiving a degraded
            # store is still possible, but only by explicit opt-in.
            if not args.allow_unverified:
                sys.exit(3)
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_bundle_verify(args: argparse.Namespace) -> None:
    try:
        result = Regista.verify_audit_bundle_offline(args.bundle_path)
        if getattr(args, "json", False):
            _dump_json(result)
        else:
            if result["verified"]:
                print(
                    f"Bundle verified — {result['event_count']} event(s), "
                    f"{result['signatures_verified']} signature(s) verified, "
                    f"{result['signatures_unverifiable']} unverifiable "
                    f"(symmetric scheme) "
                    f"[signature_check={result['signature_check']}]."
                )
            else:
                print("Bundle verification FAILED:")
                if result["event_count"] > 0 and result["signatures_verified"] == 0:
                    # WI-267: "nothing was checked" is a failure, not a pass.
                    # Say which one it is so an operator is not left staring at
                    # an empty findings list.
                    print(
                        "  signatures: 0 of "
                        f"{result['event_count']} event signature(s) could be "
                        f"verified ({result['signatures_unverifiable']} "
                        "unverifiable). Verifying a symmetric (HMAC) signature "
                        "requires the secret, which a bundle deliberately never "
                        "carries — such a bundle proves internal consistency "
                        "and nothing cryptographic."
                    )
                if not result["bundle_hash_ok"]:
                    print(f"  bundle_hash: {result['bundle_hash_error']}")
                if not result["global_chain_ok"]:
                    print(f"  global_chain: {result['global_chain_error']}")
                if not result["work_item_chain_ok"]:
                    print(f"  work_item_chain: {result['work_item_chain_error']}")
                for err in result.get("errors", []):
                    print(f"  {err}")
        # Contract §2: a bundle that does not verify is a failure whatever the
        # output format. Only the human branch used to exit 1, so an auditor
        # scripting `bundle verify --json` got exit 0 on a bundle whose body said
        # every signature failed.
        if not result["verified"]:
            print("error: bundle verification failed", file=sys.stderr)
            sys.exit(1)
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))


def cmd_workflow_compose(args: argparse.Namespace) -> None:
    from regista._workflow_compose import compose_workflow as _compose

    try:
        composed, source_map = _compose(args.file)
        if args.json:
            _dump_json({"composed": composed, "source_map": source_map})
        else:
            print(f"Composed workflow: {composed.get('name', '?')} v{composed.get('version', '?')}")
            for source in source_map.get("sources", []):  # type: ignore[attr-defined]
                print(f"  included: {source}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _print_help_and_exit(parser: argparse.ArgumentParser, code: int = 2) -> NoReturn:
    parser.print_help()
    sys.exit(code)


def cmd_work_item_create(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_work_item_transition(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_webhook_register(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_webhook_list(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        result = sub.list_webhooks(status=args.__dict__.get("status"))
        if not result:
            print("No webhooks registered.")
            return
        for w in result:
            print(f"  {str(w['webhook_id'])[:8]}...  {w['url'][:50]:<50}  {w['status']}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_webhook_remove(args: argparse.Namespace) -> None:
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
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_version(args: argparse.Namespace) -> None:
    from regista._version_info import versions as _versions

    info = _versions()
    if args.json:
        _dump_json(info)
    else:
        print(f"regista {info.library_version}")
        print(f"  schema_version:           {info.schema_version}")
        print(f"  canonical_workflow_ver:   {info.canonical_workflow_version}")
        print(f"  writable_envelope_ver:    {info.envelope_version}")
        print(f"  canonical_workflow_hash:  {info.canonical_workflow_hash[:16]}...")
        print(f"  signing_schemes:          {', '.join(info.available_signing_schemes)}")


def cmd_doctor(args: argparse.Namespace) -> None:
    from regista._config import resolve as resolve_config
    from regista._doctor import run_doctor

    cfg = resolve_config()
    dsn = args.dsn or cfg.dsn
    project = args.project or cfg.project
    require_ssl = cfg.require_ssl

    report = run_doctor(
        dsn,
        project=project,
        require_ssl=require_ssl,
        key_path=cfg.key_path,
        secret_backend=cfg.secret_backend,
        max_projects=args.max_projects,
    )
    if args.json:
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
            sys.exit(1)


def _mask_dsn(dsn: str | None) -> str:
    if not dsn:
        return "(not set)"
    from urllib.parse import urlparse

    parsed = urlparse(dsn)
    if parsed.password:
        netloc = f"{parsed.username}:***@{parsed.hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"
        masked = parsed._replace(netloc=netloc)
        return masked.geturl()
    return dsn


def cmd_config_show(args: argparse.Namespace) -> None:
    from regista._config import resolve as resolve_config

    cfg = resolve_config()
    if args.json:
        safe = cfg.to_dict()
        safe["dsn"] = _mask_dsn(cfg.dsn)
        print(json.dumps(safe, indent=2, sort_keys=True, default=str))
    else:
        print(f"dsn:         {_mask_dsn(cfg.dsn)}")
        print(f"key_path:    {cfg.key_path or '(not set)'}")
        print(f"require_ssl: {cfg.require_ssl}")
        print(f"project:     {cfg.project or '(not set)'}")
        print(f"secret_backend: {cfg.secret_backend or 'file (default)'}")
        if cfg.source:
            print()
            print("Sources:")
            for var, src in sorted(cfg.source.items()):
                print(f"  {var}: {src}")


def _secret_backend_error(e: BaseException) -> RegistaError:
    """Map a backend SDK exception onto the error envelope (contract §4).

    Resolving a ref is a documented error path, so a backend failure must arrive
    as an envelope and exit 1 — never as a raw traceback. Before this,
    ``hvac.exceptions.Forbidden`` escaped as one, and a 403 is precisely what a
    scoped AppRole policy produces when a ref reaches outside it, so this path
    gets busier once AppRole is in use (WI-229b, WI-226).

    Only the exception *type* is reported, never its text: a backend message must
    not be able to carry secret material into the envelope (contract §3).
    """
    return RegistaError(
        ErrorCode.SECRET_RESOLVE_FAILED,
        f"secret backend failed while handling the reference "
        f"({type(e).__name__}). This is the backend refusing or failing, not a "
        f"malformed ref; check the credential's policy and the backend's "
        f"reachability.",
    )


def _print_vault_auth_status(status: dict[str, Any]) -> None:
    print(f"vault provider available: {status.get('provider_available')}")
    print(f"VAULT_ADDR set:           {status.get('vault_addr_set')}")
    print(f"configured auth method:   {status.get('configured_method') or '(none)'}")
    if status.get("configured_method") == "approle":
        print(f"  role_id from:           {status.get('role_id_source')}")
        print(f"  secret_id from:         {status.get('secret_id_source')}")
        print(f"  approle mount:          auth/{status.get('approle_mount')}")
    if status.get("token_source"):
        print(f"  token from:             {status.get('token_source')}")
    print(f"active auth method:       {status.get('active_method') or '(not yet used)'}")
    print(f"lease (seconds):          {status.get('lease_duration_seconds')}")
    print(f"expires in (seconds):     {status.get('expires_in_seconds')}")
    print(f"can re-authenticate:      {status.get('reauthenticatable')}")
    print(f"logins this process:      {status.get('logins')}")
    if status.get("configured_error"):
        print(f"problem:                  {status['configured_error']}")
    if status.get("probe_error"):
        print(f"probe:                    FAILED — {status['probe_error']}")


def cmd_secrets_resolve(args: argparse.Namespace) -> None:
    from regista._secrets import available_providers
    from regista._secrets import resolve as resolve_secret

    json_mode = getattr(args, "json", False)
    if getattr(args, "auth_status", False):
        from regista._secrets import vault_auth_status

        probe = getattr(args, "probe", False)
        status = vault_auth_status(probe=probe)
        if json_mode:
            _dump_json(status)
        else:
            _print_vault_auth_status(status)
        # Contract §2: a probe that could not authenticate is an operational
        # failure and must not exit 0. A report without --probe describes
        # configuration honestly and exits 0 even when that configuration is
        # unusable — the body is what says so.
        if probe and status.get("probe_ok") is False:
            print(
                f"error: vault authentication probe failed: {status.get('probe_error')}",
                file=sys.stderr,
            )
            sys.exit(1)
        return
    if args.list_providers:
        if json_mode:
            _dump_json({"providers": available_providers()})
        else:
            print("Available providers:")
            for p in available_providers():
                print(f"  {p}")
        return
    if not args.ref:
        print(
            "Error: --ref is required (or --list-providers / --auth-status)",
            file=sys.stderr,
        )
        sys.exit(2)
    if getattr(args, "delete", False):
        from regista._secrets import DeleteOutcome
        from regista._secrets import delete as delete_secret

        try:
            outcome = delete_secret(args.ref)
        except RegistaError as e:
            _handle_error(e, json_mode=json_mode)
            return
        except Exception as e:
            _handle_error(_secret_backend_error(e), json_mode=json_mode)
            return
        if args.json:
            _dump_json({"ref": args.ref, "outcome": outcome.value})
        elif outcome is DeleteOutcome.DELETED:
            print(f"Deleted custodied secret at {args.ref}")
        elif outcome is DeleteOutcome.ALREADY_ABSENT:
            print(f"No custodied secret at {args.ref} (already absent)")
        else:
            # Saying "deleted" here would tell an operator the key is gone
            # while every copy of the reference still contains it.
            print(
                f"{args.ref} carries the secret in the reference itself; "
                f"nothing was stored to delete — discard the reference"
            )
        return
    try:
        data = resolve_secret(args.ref)
    except RegistaError as e:
        _handle_error(e, json_mode=json_mode)
        return
    except Exception as e:
        # WI-229b: this used to catch RegistaError only, so a backend refusal
        # (hvac.exceptions.Forbidden on a 403) left the process as a traceback
        # with no envelope for the caller to parse.
        _handle_error(_secret_backend_error(e), json_mode=json_mode)
        return
    if args.hex:
        print(data.hex())
    else:
        try:
            print(data.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"(binary, {len(data)} bytes) {data.hex()[:64]}...", file=sys.stderr)


def cmd_keys_fingerprint(args: argparse.Namespace) -> None:
    """Print each signing key's id, source and EFFECTIVE-bytes fingerprint.

    This is the operator-facing before/after equality primitive for key
    custody changes (WI-236): run it before a migration and again after; if a
    key_id's ``fingerprint`` field is unchanged, its effective signing key is
    byte-for-byte identical. ``--json`` output is stable and parseable
    (``{"key_path": ..., "keys": [{"key_id", "source", "scheme", "status",
    "principal_id", "encoding", "fingerprint"}, ...]}``) precisely so that
    comparison can be scripted.

    The fingerprint digests the EFFECTIVE key bytes — a key stored without
    ``encoding`` is used textually even when it looks base64, and the
    fingerprint reflects that. The key path resolves the same way doctor's
    does (WI-225): ``--hmac-key-path``, then ``REGISTA_KEY_PATH`` (legacy
    alias and suite.env included) via ``regista._config.resolve``. Never
    prints key material — source kinds and digests only.
    """
    from regista._config import resolve as resolve_config
    from regista._doctor import _resolve_key_file_path
    from regista._keys import KeySet

    key_path = args.hmac_key_path or resolve_config().key_path
    if not key_path:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "No key path configured: pass --hmac-key-path or set "
            "REGISTA_KEY_PATH (env or suite.env).",
        )
    fs_path = _resolve_key_file_path(key_path)
    if fs_path is None:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"Cannot resolve key path {key_path!r} to a filesystem path",
        )
    rows = KeySet(fs_path).describe_keys()
    if args.key_id:
        rows = [r for r in rows if r["key_id"] == args.key_id]
        if not rows:
            raise RegistaError(
                ErrorCode.UNKNOWN_KEY_ID,
                f"Unknown key_id: {args.key_id!r}",
            )
    if args.json:
        _dump_json({"key_path": fs_path, "keys": rows})
    else:
        for r in rows:
            print(f"{r['key_id']}")
            print(f"  source:       {r['source']}")
            print(f"  scheme:       {r['scheme']}")
            print(f"  status:       {r['status']}")
            print(f"  encoding:     {r['encoding'] or '(none — textual bytes)'}")
            print(f"  fingerprint:  {r['fingerprint']}")


def cmd_assurance(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    try:
        work_item_id = uuid.UUID(args.id)
    except ValueError:
        print(f"Invalid work item ID: {args.id!r}", file=sys.stderr)
        sys.exit(1)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        profile = "strict" if args.strict else "relaxed"
        level = sub.compute_assurance(work_item_id)
        rationale = sub.gate_rationale(work_item_id, profile=profile)
        if args.json:
            output = {
                "assurance_level": level.value,
                "rationale": rationale,
            }
            print(json.dumps(output, indent=2, sort_keys=True, default=str))
        else:
            print(f"Assurance level: {level.value}")
            print(f"Profile:          {rationale['profile']}")
            print(f"Reason:           {rationale['reason']}")
            reviewer = rationale.get("reviewer_lineage")
            print(f"Reviewer lineage: {reviewer or '(none)'}")
            authors = rationale.get("author_lineages", [])
            print(f"Author lineages:  {', '.join(authors) if authors else '(none)'}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_invariants_probe(args: argparse.Namespace) -> None:
    from regista._invariant_probe import discover_projects, invariant_probe_report

    dsn, configured_project, _ = _resolve_config(args)
    if not dsn:
        print("Missing required config: --dsn or REGISTA_DSN", file=sys.stderr)
        sys.exit(2)
    projects = [configured_project] if configured_project else discover_projects(dsn)
    if not projects:
        raise RegistaError(ErrorCode.DB_NOT_FOUND, "No regista projects discovered")
    report = invariant_probe_report(dsn, projects)
    if args.json:
        _dump_json(report)
    else:
        for measurement in report["checks"][0]["projects"]:
            coverage = measurement["lineage_coverage"]
            print(f"Project: {measurement['project']}")
            print(f"  events: {measurement['event_count']}")
            print(
                "  lineage: "
                f"{coverage['numerator']}/{coverage['denominator']} declared"
            )
            print(
                "  unresolvable lineage values: "
                f"{measurement['unresolvable_lineage_value_count']}"
            )
            print(
                "  undeclared agent authors: "
                f"{measurement['undeclared_agent_author_event_count']}"
            )
            print(f"  schemes: {measurement['scheme_counts']}")
    if not report["ok"]:
        sys.exit(1)


def cmd_principal_list(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        from regista._principal_keys import list_principal_keys

        entries = list_principal_keys(sub._mgr, principal_id=args.principal, status=args.status)
        if args.json:
            _dump_json(entries)
        else:
            for e in entries:
                print(
                    f"{e.principal_id:20s} {e.key_id:20s} {e.scheme:12s} "
                    f"{e.status:10s} {e.fingerprint[:16]}..."
                )
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_principal_register(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    import base64

    sub = Regista(dsn, project, hmac_key_path)
    try:
        from regista._principal_keys import register_principal_key

        pub_key = base64.b64decode(args.public_key)
        entry = register_principal_key(
            sub._mgr,
            args.principal,
            pub_key,
            args.scheme,
            key_id=args.key_id,
            registered_by=args.registered_by or "cli",
        )
        if args.json:
            _dump_json(entry)
        else:
            print(f"Registered key {entry.key_id} for principal {entry.principal_id}")
            print(f"  scheme:      {entry.scheme}")
            print(f"  fingerprint: {entry.fingerprint}")
            print(f"  status:      {entry.status}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_principal_rotate(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    import base64

    sub = Regista(dsn, project, hmac_key_path)
    try:
        from regista._principal_keys import rotate_principal_key

        pub_key = base64.b64decode(args.public_key)
        entry = rotate_principal_key(
            sub._mgr,
            args.principal,
            pub_key,
            args.scheme,
            registered_by=args.registered_by or "cli",
        )
        if args.json:
            _dump_json(entry)
        else:
            print(f"Rotated key for principal {entry.principal_id}:")
            print(f"  new key_id:  {entry.key_id}")
            print(f"  scheme:      {entry.scheme}")
            print(f"  fingerprint: {entry.fingerprint}")
            print(f"  status:      {entry.status}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_principal_enroll(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        result = sub.enroll_principal(
            args.principal,
            private_key_dir=args.private_key_dir,
            secret_backend=args.secret_backend,
        )
        if args.json:
            _dump_json(result)
        else:
            if result["already_existed"]:
                print(f"Principal {result['principal_id']} already has an active key:")
            else:
                print(f"Enrolled principal {result['principal_id']}:")
            print(f"  key_id:      {result['key_id']}")
            print(f"  fingerprint: {result['fingerprint']}")
            print(f"  scheme:      {result['scheme']}")
            print(f"  backend:     {result['secret_backend']}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_principal_revoke(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        from regista._principal_keys import revoke_principal_key

        entry = revoke_principal_key(
            sub._mgr,
            args.principal,
            args.key_id,
            reason=args.reason or "unspecified",
        )
        if args.json:
            _dump_json(entry)
        else:
            print(f"Revoked key {entry.key_id} for principal {entry.principal_id}")
            print(f"  reason:      {entry.revoked_reason}")
            print(f"  revoked_at:  {entry.revoked_at}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_provision(args: argparse.Namespace) -> None:
    from regista._config import resolve as resolve_config
    from regista._provision import provision as _provision

    cfg = resolve_config()
    dsn = args.dsn or cfg.dsn
    if not dsn:
        print("Missing required config: --dsn or REGISTA_DSN", file=sys.stderr)
        sys.exit(2)
    projects = args.projects or ([cfg.project] if cfg.project else [])
    if not projects:
        print("Missing required: --project or REGISTA_PROJECT", file=sys.stderr)
        sys.exit(2)

    results = _provision(dsn, projects, dry_run=args.dry_run)
    if args.json:
        _dump_json(results)
    else:
        for r in results:
            if r.error:
                print(f"[FAIL] {r.project}: {r.error}")
            else:
                actions = []
                if r.schema_created:
                    actions.append("schema created")
                else:
                    actions.append("schema exists")
                if r.migrations_applied:
                    actions.append(f"migrations: {r.migrations_applied}")
                if r.service_role_created:
                    actions.append("service role created")
                else:
                    actions.append("service role exists")
                print(f"[OK] {r.project}: {', '.join(actions)}")
    # Contract §2: the exit code is decided by the *results*, not by the output
    # format. This used to sit inside the `else`, so `provision --json` exited 0
    # while its body said the service role was never created — which is how
    # `agent-suite bootstrap` reported OK over a provision that did nothing
    # (agent-suite WI-040). Partial success picks a side: any failed project
    # fails the verb.
    failed = [r for r in results if r.error]
    if failed:
        names = ", ".join(r.project for r in failed)
        print(
            f"error: provision failed for {len(failed)} of {len(results)} "
            f"project(s): {names}",
            file=sys.stderr,
        )
        sys.exit(1)


def cmd_provision_principal(args: argparse.Namespace) -> None:
    from regista._config import resolve as resolve_config
    from regista._provision import provision_principal as _provision_principal

    cfg = resolve_config()
    dsn = args.dsn or cfg.dsn
    if not dsn:
        print("Missing required config: --dsn or REGISTA_DSN", file=sys.stderr)
        sys.exit(2)
    project = args.project or cfg.project
    if not project:
        print("Missing required: --project or REGISTA_PROJECT", file=sys.stderr)
        sys.exit(2)
    key_path = args.hmac_key_path or cfg.key_path

    result = _provision_principal(
        dsn,
        project,
        args.principal,
        hmac_key_path=key_path,
        private_key_dir=args.private_key_dir,
        secret_backend=args.secret_backend or cfg.secret_backend,
        dry_run=args.dry_run,
        reuse_existing_key=args.reuse_existing_key,
    )
    if result.error:
        # Same contract §2 fix as `provision`: the failure was only ever acted on
        # in the human branch, so `--json` reported the error and exited 0.
        _fail_json(
            result,
            json_mode=args.json,
            diagnostic=f"error: provision-principal failed: {result.error}",
        )
    if args.json:
        _dump_json(result)
    else:
        if result.already_existed:
            print(f"Principal {result.principal_id} already has an active key:")
            print(f"  key_id:      {result.key_id}")
            print(f"  fingerprint: {result.fingerprint}")
        else:
            print(f"Provisioned principal {result.principal_id}:")
            print(f"  key_id:      {result.key_id}")
            print(f"  fingerprint: {result.fingerprint}")
            print(f"  private key stored: {result.private_key_stored}")
            print(f"  public key registered: {result.public_key_registered}")


def cmd_signer_generate(args: argparse.Namespace) -> None:
    from regista.client_signer import ClientSigner

    try:
        signer = ClientSigner.generate(
            args.principal,
            backend=args.secret_backend,
            project=args.project,
            private_key_dir=args.private_key_dir,
        )
        if args.json:
            _dump_json(signer.identity)
        else:
            print(f"Generated signing key for principal {signer.identity.principal_id}:")
            print(f"  fingerprint: {signer.identity.fingerprint}")
            print(f"  scheme:      {signer.identity.scheme}")
            print(f"  custody:     {signer.identity.custody_mode}")
            print(f"  secret_ref:  {signer.identity.secret_ref}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))


def cmd_signer_sign_possession(args: argparse.Namespace) -> None:
    import json as json_mod

    from regista.client_signer import ClientSigner
    from regista.principal_lifecycle import PossessionChallenge

    try:
        signer = ClientSigner.load(
            args.principal,
            args.secret_ref,
            custody_mode=args.custody_mode,
        )
        challenge_json = args.challenge
        if challenge_json is None:
            challenge_json = sys.stdin.read()
        if not challenge_json or not challenge_json.strip():
            print("No challenge provided (use --challenge or stdin)", file=sys.stderr)
            sys.exit(2)
        challenge_data = json_mod.loads(challenge_json)
        if not isinstance(challenge_data, dict):
            print("[ERROR] Challenge JSON must be an object", file=sys.stderr)
            sys.exit(1)
        challenge = PossessionChallenge(
            challenge_id=challenge_data["challenge_id"],
            operation_id=challenge_data["operation_id"],
            operation_digest=challenge_data["operation_digest"],
            project=challenge_data["project"],
            principal_id=challenge_data["principal_id"],
            fingerprint=challenge_data["fingerprint"],
            scheme=challenge_data["scheme"],
            verifier_nonce=challenge_data["verifier_nonce"],
            issued_at=_parse_iso(challenge_data["issued_at"]),
            expires_at=_parse_iso(challenge_data["expires_at"]),
        )
        proof = signer.sign_possession(challenge)
        if args.json:
            _dump_json(proof)
        else:
            print(f"Signed possession challenge {proof.challenge_id}:")
            print(f"  operation_id: {proof.operation_id}")
            print(f"  signature:    {base64.b64encode(proof.signature).decode('ascii')[:32]}...")
    except (RegistaError, ValueError, KeyError) as e:
        if isinstance(e, RegistaError):
            _handle_error(e, json_mode=getattr(args, "json", False))
        elif isinstance(e, KeyError):
            print(f"[ERROR] Missing required field in challenge JSON: {e}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[ERROR] {e}", file=sys.stderr)
            sys.exit(1)


def cmd_signer_sign_effective(args: argparse.Namespace) -> None:
    import json as json_mod

    from regista.client_signer import ClientSigner
    from regista.principal_lifecycle import EffectiveChallenge

    try:
        signer = ClientSigner.load(
            args.principal,
            args.secret_ref,
            custody_mode=args.custody_mode,
        )
        challenge_json = args.challenge
        if challenge_json is None:
            challenge_json = sys.stdin.read()
        if not challenge_json or not challenge_json.strip():
            print("No challenge provided (use --challenge or stdin)", file=sys.stderr)
            sys.exit(2)
        challenge_data = json_mod.loads(challenge_json)
        if not isinstance(challenge_data, dict):
            print("[ERROR] Challenge JSON must be an object", file=sys.stderr)
            sys.exit(1)
        challenge = EffectiveChallenge(
            challenge_id=challenge_data["challenge_id"],
            operation_id=challenge_data["operation_id"],
            operation_digest=challenge_data["operation_digest"],
            project=challenge_data["project"],
            principal_id=challenge_data["principal_id"],
            fingerprint=challenge_data["fingerprint"],
            scheme=challenge_data["scheme"],
            verifier_nonce=challenge_data["verifier_nonce"],
            issued_at=_parse_iso(challenge_data["issued_at"]),
            expires_at=_parse_iso(challenge_data["expires_at"]),
        )
        receipt = signer.sign_effective(challenge)
        if args.json:
            _dump_json(receipt)
        else:
            print(f"Effective-use receipt for operation {receipt.operation_id}:")
            print(f"  status:       {receipt.status.value}")
            print(f"  fingerprint:  {receipt.fingerprint}")
            print(f"  client_type:  {receipt.client_type}")
            print(f"  challenge_id: {receipt.challenge_id}")
            print(f"  observed_at:  {receipt.observed_at.isoformat()}")
    except (RegistaError, ValueError, KeyError) as e:
        if isinstance(e, RegistaError):
            _handle_error(e, json_mode=getattr(args, "json", False))
        elif isinstance(e, KeyError):
            print(f"[ERROR] Missing required field in challenge JSON: {e}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[ERROR] {e}", file=sys.stderr)
            sys.exit(1)


def _parse_iso(value: object) -> datetime:
    from datetime import datetime as dt

    if not isinstance(value, str):
        raise ValueError(f"Expected an ISO-8601 timestamp string, got {type(value).__name__}")
    return dt.fromisoformat(value.replace("Z", "+00:00"))


def cmd_spec_sign(args: argparse.Namespace) -> None:
    import hashlib

    try:
        with open(args.spec_file) as f:
            spec_yaml = f.read()
    except FileNotFoundError:
        print(f"File not found: {args.spec_file}", file=sys.stderr)
        sys.exit(1)

    if args.spec_md_file:
        with open(args.spec_md_file, "rb") as f:
            spec_md_hash = hashlib.sha256(f.read()).hexdigest()
    else:
        spec_md_hash = args.spec_md_hash or ""

    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        evt = sub.sign_spec(
            spec_yaml=spec_yaml,
            spec_md_hash=spec_md_hash,
            spec_schema_version=args.schema_version,
            actor_id=args.actor_id,
            actor_kind=args.actor_kind,
            spec_id=uuid.UUID(args.spec_id) if args.spec_id else None,
        )
        if args.json:
            _dump_json(evt)
        else:
            print(f"Spec signed: event_id={evt.event_id}")
            print(f"  entity_id:   {evt.effective_entity_id}")
            print(f"  event_seq:   {evt.event_seq}")
            print(f"  transition:  {evt.transition}")
            print(f"  timestamp:   {evt.timestamp.isoformat()}")
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_spec_events(args: argparse.Namespace) -> None:
    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        events = sub.read_spec_events(
            spec_id=uuid.UUID(args.spec_id) if args.spec_id else None,
            limit=args.limit,
        )
        if args.json:
            _dump_json([e.to_dict() for e in events])
        else:
            if not events:
                print("No spec events found.")
                return
            for evt in events:
                payload = evt.payload or {}
                print(f"  {evt.timestamp.isoformat()}  seq={evt.event_seq}")
                print(f"    event_id:    {evt.event_id}")
                print(f"    entity_id:   {evt.effective_entity_id}")
                print(f"    actor:       {evt.actor_id}")
                print(f"    version:     {payload.get('spec_schema_version', '?')}")
                print(f"    md_hash:     {payload.get('spec_md_hash', '?')[:16]}...")
                print()
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def main(argv: list[str] | None = None) -> None:
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

    # bundle
    bnd = subs.add_parser("bundle", help="Audit bundle export and verification")
    bnd_sub = bnd.add_subparsers(dest="subcommand")
    bnd_export = bnd_sub.add_parser("export", help="Export an audit bundle")
    bnd_export.add_argument(
        "--output", required=True, help="Output JSON file path (bundle is canonical JSON)"
    )
    bnd_export.add_argument(
        "--since-seq", type=int, default=None,
        help="Export events with global_seq strictly after this (exclusive lower bound)",
    )
    bnd_export.add_argument(
        "--until-seq", type=int, default=None,
        help="Export events with global_seq up to and including this (inclusive "
        "upper bound); with --since-seq, chunks a corpus larger than the "
        "offline verifier's size cap into verifiable pieces",
    )
    bnd_export.add_argument(
        "--allow-unverified", action="store_true",
        help="Exit 0 even when the written artifact fails offline "
        "verification for store-level reasons (e.g. a key registry predating "
        "its migration). Default: the artifact is written but the command "
        "exits 3, so pipelines cannot mistake an unverifiable export for a "
        "verified one",
    )
    bnd_export.add_argument("--json", action="store_true", help="JSON output")
    bnd_export.set_defaults(func=cmd_bundle_export)

    bnd_verify = bnd_sub.add_parser("verify", help="Verify an audit bundle offline")
    bnd_verify.add_argument("bundle_path", help="Path to bundle JSON file")
    bnd_verify.add_argument("--json", action="store_true", help="JSON output")
    bnd_verify.set_defaults(func=cmd_bundle_verify)

    # replay
    rep = subs.add_parser("replay", help="Run replay drift check")
    rep.add_argument("--continue-on-revoked", action="store_true", help="Skip revoked-key events")
    rep.add_argument(
        "--verify-principal-binding",
        action="store_true",
        help="Deprecated no-op: the principal_keys binding check is on by "
        "default (WI-223). Kept so existing invocations keep working.",
    )
    rep.add_argument(
        "--no-verify-principal-binding",
        action="store_true",
        help="Skip the principal_keys binding check. The report then says "
        "principal_binding=not-verified rather than claiming zero failures.",
    )
    rep.add_argument(
        "--strict-principal-binding",
        action="store_true",
        help="Exit non-zero when --verify-principal-binding reports any "
        "principal-binding failure (default: report as warnings only, "
        "backward compatible with HMAC-only deployments)",
    )
    rep.add_argument(
        "--read-only",
        action="store_true",
        help="Intended for use against a read-only connection (hot standby / "
        "restore). regista will not issue DDL and replay runs entirely in "
        "memory, but the no-mutates guarantee holds only if the DSN session "
        "is actually read-only. The schema's migrations table is probed and "
        "the command fails closed if it is missing.",
    )
    rep.set_defaults(func=cmd_replay)

    # schema
    sc = subs.add_parser("schema", help="Schema commands")
    sc_sub = sc.add_subparsers(dest="subcommand")
    sc_sub.add_parser("init", help="Initialize schema").set_defaults(func=cmd_schema_init)
    sc_sub.add_parser("status", help="Schema status").set_defaults(func=cmd_schema_status)
    sc_sub.add_parser(
        "repair-checksums", help="Repair migration checksums after file edits"
    ).set_defaults(func=cmd_schema_repair_checksums)

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

    # version
    ver_parser = subs.add_parser("version", help="Show regista version info")
    ver_parser.add_argument("--json", action="store_true", help="JSON output")
    ver_parser.set_defaults(func=cmd_version)

    # doctor
    doc_parser = subs.add_parser("doctor", help="Health check")
    doc_parser.add_argument("--json", action="store_true", help="JSON output")
    doc_parser.add_argument(
        "--max-projects", type=int, default=25,
        help="Upper bound on projects checked individually without --project "
             "(default 25)",
    )
    doc_parser.set_defaults(func=cmd_doctor)

    # config
    cfg_parser = subs.add_parser("config", help="Show resolved config")
    cfg_parser.add_argument("--json", action="store_true", help="JSON output")
    cfg_parser.set_defaults(func=cmd_config_show)

    # secrets
    sec_parser = subs.add_parser("secrets", help="Resolve a secret reference")
    sec_parser.add_argument(
        "--ref",
        help="Secret reference (e.g. file:/path, env:VAR, vault:mount/path/key)",
    )
    sec_parser.add_argument("--hex", action="store_true", help="Output as hex")
    sec_parser.add_argument(
        "--list-providers",
        action="store_true",
        help="List available secret providers",
    )
    sec_parser.add_argument(
        "--auth-status",
        action="store_true",
        help=(
            "Report which Vault auth method this process uses (approle or the "
            "dev-only static token), where each credential came from, and the "
            "current token lease. Never prints credential values"
        ),
    )
    sec_parser.add_argument(
        "--probe",
        action="store_true",
        help=(
            "With --auth-status, actually authenticate so the report "
            "distinguishes 'AppRole is declared' from 'AppRole works'. "
            "Exits 1 if authentication fails"
        ),
    )
    sec_parser.add_argument(
        "--delete",
        action="store_true",
        help=(
            "Delete the custodied secret at --ref instead of resolving it. "
            "Idempotent. Backends whose reference carries the secret itself "
            "(windows, literal) report 'inline_ref' — discard the reference"
        ),
    )
    sec_parser.set_defaults(func=cmd_secrets_resolve)

    # keys (WI-236 — operator fingerprint surface over the signing keyset)
    keys_parser = subs.add_parser("keys", help="Signing keyset commands")
    keys_sub = keys_parser.add_subparsers(dest="subcommand")
    keys_fp = keys_sub.add_parser(
        "fingerprint",
        help="Print each key's id, material source (inline/env/secret_ref), "
        "declared encoding and the fingerprint of its EFFECTIVE key bytes — "
        "never the material. Stable --json output supports scripted "
        "before/after equality checks around custody changes",
    )
    keys_fp.add_argument("key_id", nargs="?", help="Only this key id")
    keys_fp.add_argument("--json", action="store_true", help="JSON output")
    keys_fp.set_defaults(func=cmd_keys_fingerprint)

    # assurance (Plan 027)
    assurance_parser = subs.add_parser(
        "assurance",
        help="Compute review assurance level for a work item",
    )
    assurance_parser.add_argument("id", help="Work item UUID")
    assurance_parser.add_argument(
        "--strict",
        action="store_true",
        help="Use the strict gate profile (same-lineage review requires human accept)",
    )
    assurance_parser.add_argument("--json", action="store_true", help="JSON output")
    assurance_parser.set_defaults(func=cmd_assurance)

    invariants_parser = subs.add_parser(
        "invariants", help="Read-only evidentiary invariant measurements"
    )
    invariants_sub = invariants_parser.add_subparsers(dest="subcommand")
    invariants_probe_parser = invariants_sub.add_parser(
        "probe", help="Measure event-store invariants"
    )
    invariants_probe_parser.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )
    invariants_probe_parser.set_defaults(func=cmd_invariants_probe)

    # principal (Plan 026)
    pr_parser = subs.add_parser("principal", help="Principal key registry commands")
    pr_sub = pr_parser.add_subparsers(dest="subcommand")
    pr_list = pr_sub.add_parser("list", help="List principal keys")
    pr_list.add_argument("--principal", help="Filter by principal_id")
    pr_list.add_argument("--status", help="Filter by status (active/revoked/superseded)")
    pr_list.set_defaults(func=cmd_principal_list)
    pr_reg = pr_sub.add_parser("register", help="Register a principal public key")
    pr_reg.add_argument("--principal", required=True, help="Principal ID")
    pr_reg.add_argument("--public-key", required=True, help="Base64-encoded public key")
    pr_reg.add_argument("--scheme", default="ed25519", help="Signing scheme (default: ed25519)")
    pr_reg.add_argument("--key-id", help="Optional key ID")
    pr_reg.add_argument("--registered-by", help="Who is registering this key")
    pr_reg.set_defaults(func=cmd_principal_register)
    pr_rot = pr_sub.add_parser(
        "rotate",
        help="Rotate a principal to a new public key (supersedes the active key)",
    )
    pr_rot.add_argument("--principal", required=True, help="Principal ID")
    pr_rot.add_argument("--public-key", required=True, help="Base64-encoded new public key")
    pr_rot.add_argument("--scheme", default="ed25519", help="Signing scheme (default: ed25519)")
    pr_rot.add_argument("--registered-by", help="Who is rotating this key")
    pr_rot.set_defaults(func=cmd_principal_rotate)
    pr_enroll = pr_sub.add_parser("enroll", help="Issue and register a per-principal Ed25519 key")
    pr_enroll.add_argument("--principal", required=True, help="Principal ID")
    pr_enroll.add_argument("--private-key-dir", help="Directory for private key files")
    pr_enroll.add_argument(
        "--secret-backend",
        help="Secret backend for key custody: file/windows/vault/azure/operator "
        "(or REGISTA_SECRET_BACKEND)",
    )
    pr_enroll.set_defaults(func=cmd_principal_enroll)
    pr_revoke = pr_sub.add_parser("revoke", help="Revoke a principal key")
    pr_revoke.add_argument("--principal", required=True, help="Principal ID")
    pr_revoke.add_argument("--key-id", required=True, help="Key ID to revoke")
    pr_revoke.add_argument("--reason", help="Revocation reason")
    pr_revoke.set_defaults(func=cmd_principal_revoke)

    # signer (Plan 031 §5 — client-side custody/signing helper)
    sg_parser = subs.add_parser("signer", help="Client-side key custody and signing")
    sg_sub = sg_parser.add_subparsers(dest="subcommand")
    sg_gen = sg_sub.add_parser("generate", help="Generate and custody a new Ed25519 keypair")
    sg_gen.add_argument("--principal", required=True, help="Principal ID")
    sg_gen.add_argument("--project", help="Project slug (for vault/azure ref naming)")
    sg_gen.add_argument("--private-key-dir", help="Directory for private key files (file backend)")
    sg_gen.add_argument(
        "--secret-backend",
        help="Secret backend for key custody: file/windows/vault/azure (or REGISTA_SECRET_BACKEND)",
    )
    sg_gen.add_argument("--json", action="store_true", help="JSON output")
    sg_gen.set_defaults(func=cmd_signer_generate)
    sg_sign_poss = sg_sub.add_parser(
        "sign-possession",
        help="Sign a possession challenge (JSON on stdin or --challenge)",
    )
    sg_sign_poss.add_argument("--principal", required=True, help="Principal ID")
    sg_sign_poss.add_argument(
        "--secret-ref",
        required=True,
        help="Secret reference for the private key",
    )
    sg_sign_poss.add_argument(
        "--custody-mode",
        help="Custody mode label (file/windows_local/remote_organizational)",
    )
    sg_sign_poss.add_argument(
        "--challenge",
        help="Possession challenge as JSON (or read from stdin)",
    )
    sg_sign_poss.add_argument("--json", action="store_true", help="JSON output")
    sg_sign_poss.set_defaults(func=cmd_signer_sign_possession)
    sg_sign_eff = sg_sub.add_parser("sign-effective", help="Produce an effective-use receipt")
    sg_sign_eff.add_argument("--principal", required=True, help="Principal ID")
    sg_sign_eff.add_argument(
        "--secret-ref",
        required=True,
        help="Secret reference for the private key",
    )
    sg_sign_eff.add_argument("--custody-mode", help="Custody mode label")
    sg_sign_eff.add_argument(
        "--challenge",
        help="Effective challenge as JSON (or read from stdin)",
    )
    sg_sign_eff.add_argument("--json", action="store_true", help="JSON output")
    sg_sign_eff.set_defaults(func=cmd_signer_sign_effective)

    # provision (Plan 025 WI-2.1)
    prov_parser = subs.add_parser("provision", help="Provision project schemas and service roles")
    prov_parser.add_argument(
        "--project",
        action="append",
        dest="projects",
        help="Project slug (can be repeated for multiple projects)",
    )
    prov_parser.add_argument("--dry-run", action="store_true", help="Print plan without writing")
    prov_parser.add_argument("--json", action="store_true", help="JSON output")
    prov_parser.set_defaults(func=cmd_provision)

    # provision-principal (Plan 025 WI-2.1 + Plan 026)
    prov_princ_parser = subs.add_parser(
        "provision-principal",
        help="Issue and register a per-principal Ed25519 key",
    )
    prov_princ_parser.add_argument("--principal", required=True, help="Principal ID")
    prov_princ_parser.add_argument("--project", help="Project slug (or REGISTA_PROJECT)")
    prov_princ_parser.add_argument("--private-key-dir", help="Directory for private key files")
    prov_princ_parser.add_argument(
        "--secret-backend",
        help="Secret backend for key custody: file/windows/vault/azure/operator "
        "(or REGISTA_SECRET_BACKEND)",
    )
    prov_princ_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print plan without writing",
    )
    prov_princ_parser.add_argument(
        "--reuse-existing-key",
        action="store_true",
        help="Register the public key already in the signing key file for this "
        "principal instead of minting a new keypair. Required when the same "
        "principal acts in a second project that shares the key file — minting "
        "a second keypair would leave the first project's chain signed by a key "
        "it never registered (WI-223).",
    )
    prov_princ_parser.add_argument("--json", action="store_true", help="JSON output")
    prov_princ_parser.set_defaults(func=cmd_provision_principal)

    # spec (Plan 025 WI-4.3)
    spec_parser = subs.add_parser("spec", help="Spec entity commands")
    spec_sub = spec_parser.add_subparsers(dest="subcommand")
    spec_sign = spec_sub.add_parser("sign", help="Sign a spec.yaml into the project")
    spec_sign.add_argument("spec_file", help="Path to spec.yaml")
    spec_sign.add_argument("--schema-version", required=True, help="Spec schema version")
    spec_sign.add_argument("--spec-md-file", help="Path to spec.md (hash computed automatically)")
    spec_sign.add_argument(
        "--spec-md-hash",
        help="Hex hash of spec.md (alternative to --spec-md-file)",
    )
    spec_sign.add_argument("--actor-id", required=True, help="Actor ID")
    spec_sign.add_argument("--actor-kind", default="system", help="Actor kind (agent/human/system)")
    spec_sign.add_argument("--spec-id", help="UUID for the spec entity (auto-generated if omitted)")
    spec_sign.add_argument("--json", action="store_true", help="JSON output")
    spec_sign.set_defaults(func=cmd_spec_sign)
    spec_list = spec_sub.add_parser("events", help="List spec events")
    spec_list.add_argument("--spec-id", help="Filter by spec entity UUID")
    spec_list.add_argument("--limit", type=int, default=100)
    spec_list.add_argument("--json", action="store_true", help="JSON output")
    spec_list.set_defaults(func=cmd_spec_events)

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(2)

    if hasattr(args, "func"):
        # Contract §3/§5 boundary: any RegistaError that escapes a command
        # handler (e.g. raised while constructing Regista(), before the
        # handler's own try/except) is reported through the common error
        # envelope and exit 1 — never as an uncaught traceback.
        try:
            args.func(args)
        except RegistaError as e:
            _handle_error(e, json_mode=getattr(args, "json", False))
    else:
        target = subs.choices.get(args.command)
        if target:
            target.print_help()
        else:
            parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
