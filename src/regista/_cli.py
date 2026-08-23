from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import tempfile
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import structlog

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._workflow import validate_yaml as _validate_yaml

if TYPE_CHECKING:  # import-time cost stays out of the CLI's startup path
    from regista._estate_catalog import RootAuthorityState
    from regista._trust_domain import TrustGenesisDocument

#: EXACTLY six fractional digits. ``strptime("%f")`` accepts one to six, so a CLI check
#: built on it accepted ``...T12:00:00.1Z`` while promising microsecond precision
#: (WI-330 review N-b). Same shape as ``_trust_domain._TIMESTAMP_RE``.
_MICROSECOND_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")


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


#: Shared refusal text for the three CLI subcommands that used to write the
#: `principal_keys` projection directly (TRUST-DOMAIN.md §5.9, §5.1's bypass list).
_CLI_PROJECTION_REFUSAL = (
    "principal_keys is a projection of signed trust-log events (TRUST-DOMAIN.md "
    "§5.9), and this subcommand wrote it directly with no event — one of the three "
    "bypass paths the 0.6.0 cutover closes.\n\n"
    "The event-driven path is regista.principal_lifecycle.PrincipalLifecycle:\n"
    "  1. prepare_enrollment / prepare_rotation / prepare_revocation\n"
    "  2. issue_possession_challenge + submit_possession  (enrol/rotate: proves the\n"
    "     holder has the private half of the key being enrolled)\n"
    "  3. record_approval  (a distinct approver — separation of duties)\n"
    "  4. commit  (appends the signed event and applies the projection atomically)\n\n"
    "That ceremony is deliberately multi-step and needs material a single "
    "non-interactive CLI invocation does not have: the enrolling private key for the "
    "possession proof, and a second principal's approval. Driving THIS ordinary-project "
    "flow from the CLI is not wired up in 0.6.0 — see `regista trust rebuild-projection` "
    "for the read/repair side.\n\n"
    "The shipped write path for the estate trust log is `regista trust enroll`, which "
    "uses a DIFFERENT, registrar-scoped authority model (TRUST-DOMAIN.md §5.5): a live "
    "registrar's delegation IS the authority to enrol, so there is no separate approval "
    "step — the delegation, granted under root authority, already carries it. It still "
    "requires the enrollee's possession proof, and it never writes the projection "
    "directly: it appends a signed `principal_key_enrolled` event that "
    "`rebuild-projection` materialises."
)


def _refuse_principal_write(args: argparse.Namespace, operation: str, extra: str = "") -> None:
    error = RegistaError(
        ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED,
        f"`regista principal {operation}` is refused. {_CLI_PROJECTION_REFUSAL}"
        + (f"\n\n{extra}" if extra else ""),
        {"reason": "direct_projection_write", "operation": operation},
    )
    _handle_error(error, json_mode=getattr(args, "json", False))


def cmd_principal_register(args: argparse.Namespace) -> None:
    _refuse_principal_write(args, "register")


def cmd_principal_rotate(args: argparse.Namespace) -> None:
    _refuse_principal_write(
        args,
        "rotate",
        "A rotation additionally requires dual authorization: a signature by the "
        "superseded key, or the current root threshold when mode is recovery "
        "(§5.6, Resolution 5 / D-8). A --public-key argument cannot supply either.",
    )


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


def cmd_principal_resolve_backend_name(args: argparse.Namespace) -> None:
    """``regista principal resolve-backend-name <backend_name>`` — TRUST-DOMAIN.md §2.2.

    §2.2 derives a backend-safe name one-way
    (``"rp-" + hex(SHA256(domain || utf8(principal_id))[0:16])``) precisely so that
    ``:``→``-`` substitution collisions are impossible. That makes the KV tree
    unreadable by hand unless a lookup verb exists, "which the migration posture depends
    on" — this is that verb.

    Two modes:

    * with ``--principal-id``: confirm one candidate. No database needed, no secret read.
    * without: derive-and-compare over the ``principal_keys`` registry of this project.

    It never reads a secret. §2.2 stores the canonical id *inside* the secret as a field,
    but resolving from the registry needs no such read, so the resolver deliberately uses
    the non-secret registry instead of touching custody at all. The projection is a
    **cache** (§5.9 / D-6), so a ``None`` means "not among the principals this project's
    registry names", never "not a principal".
    """
    from regista._principals import backend_name, is_backend_name, resolve_backend_name

    name = args.backend_name
    if not is_backend_name(name):
        _handle_error(
            RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"{name!r} is not a regista backend name "
                f"(expected 'rp-' + 32 lowercase hex characters)",
                {"reason": "malformed_backend_name", "backend_name": name},
            ),
            json_mode=getattr(args, "json", False),
        )

    if args.principal_id:
        derived = backend_name(args.principal_id)
        matched = derived == name
        result = {
            "backend_name": name,
            "principal_id": args.principal_id if matched else None,
            "confirmed": matched,
            "derived_backend_name": derived,
            "source": "candidate",
            "candidates_considered": 1,
        }
        if args.json:
            _dump_json(result)
        elif matched:
            print(f"{name} -> {args.principal_id}")
        else:
            print(f"{name} does not derive from {args.principal_id!r} (derived {derived})")
        if not matched:
            sys.exit(1)
        return

    dsn, project, hmac_key_path = _require_config(args)
    sub = Regista(dsn, project, hmac_key_path)
    try:
        from regista._principal_keys import list_principal_keys

        # Non-secret field allowlist: only principal_id leaves the registry row here.
        candidates = sorted({e.principal_id for e in list_principal_keys(sub._mgr)})
        resolved = resolve_backend_name(name, candidates)
        result = {
            "backend_name": name,
            "principal_id": resolved,
            "confirmed": resolved is not None,
            "derived_backend_name": name if resolved is not None else None,
            "source": "principal_keys",
            "candidates_considered": len(candidates),
        }
        if args.json:
            _dump_json(result)
        elif resolved is not None:
            print(f"{name} -> {resolved}")
        else:
            print(
                f"{name} matched none of the {len(candidates)} principal(s) in "
                f"project {project!r}'s registry"
            )
        if resolved is None:
            sys.exit(1)
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
    finally:
        sub.close()


def cmd_principal_revoke(args: argparse.Namespace) -> None:
    _refuse_principal_write(
        args,
        "revoke",
        "Note also what flipping this row would not achieve: it changes no "
        "verification outcome for any v6 event. Revocation binds at the revocation "
        "event's position in the trust-log chain (§5.7), never at a table row — the "
        "table is a projection and is never consulted for a v6 event (§5.9 rule 1).",
    )


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
            # v2 fields (§5.5): the client must sign the challenge EXACTLY as issued,
            # including trust_domain_id and enrollment_request_digest, or the framed
            # signing bytes differ from the verifier's and a trust-log enrollment
            # (`regista trust enroll`) rejects the proof as unverifiable. They default
            # to None so a v1 challenge that omits them still signs the v1 bytes.
            trust_domain_id=challenge_data.get("trust_domain_id"),
            enrollment_request_digest=challenge_data.get("enrollment_request_digest"),
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


def _read_ed25519_seed(path: str) -> bytes:
    """Read a 32-byte Ed25519 seed from a file holding 64 hex chars or base64."""
    try:
        text = open(path, encoding="utf-8").read().strip()
    except OSError as e:
        raise RegistaError(ErrorCode.KEY_LOAD_ERROR, f"cannot read key file: {e}") from e
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as e:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            "key file must contain a 32-byte Ed25519 seed as 64 hex chars or base64",
        ) from e
    if len(raw) != 32:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"key file must decode to 32 seed bytes, got {len(raw)}",
        )
    return raw


def cmd_trust_sign_genesis(args: argparse.Namespace) -> None:
    """Offline ceremony helper (TRUST-DOMAIN.md §5.4): read a genesis document, print
    the exact bytes it will sign, write a detached signature. NEVER contacts a
    database and never writes to the publication repo."""
    import nacl.signing

    from regista._principal_keys import _compute_fingerprint
    from regista._trust_domain import (
        genesis_signature_input,
        parse_trust_genesis,
        require_genesis_timestamp,
    )

    # Validate --signed-at BEFORE signing anything. The verifier requires the exact
    # microsecond UTC "Z" form (TRUST-DOMAIN.md §3.2), and a malformed override was
    # previously caught only when the assembled document was parsed — i.e. after this
    # tool had already minted a detached signature entry that its own verifier
    # rejects. An offline ceremony discovers that with the keys already back in the
    # safe, so the refusal has to happen at production time.
    if args.signed_at is not None:
        require_genesis_timestamp(args.signed_at, "--signed-at")

    # Refuse to clobber an existing detached signature: in a k-of-n ceremony the
    # obvious operator slip is reusing one --out path across signers, which silently
    # destroys an already-collected signature that may be unreproducible (the key is
    # back offline). --force is the deliberate escape hatch.
    if os.path.exists(args.out) and not args.force:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"refusing to overwrite existing signature file {args.out}; "
            "choose another --out path or pass --force",
            {"reason": "output_exists", "path": args.out},
        )

    with open(args.core, encoding="utf-8") as f:
        document = json.load(f)
    # Strict parse (signatures optional at signing time): never sign a document whose
    # stated digest/id disagree with the recomputed derivation.
    parsed = parse_trust_genesis(document, for_signing=True)

    seed = _read_ed25519_seed(args.key)
    signing_key = nacl.signing.SigningKey(seed)
    fingerprint = _compute_fingerprint(bytes(signing_key.verify_key), "ed25519")
    signer = parsed.signer_by_fingerprint(fingerprint)
    if signer is None:
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
            f"key with fingerprint {fingerprint} is not a signer in binding_core",
            {"reason": "unknown_signer", "fingerprint": fingerprint},
        )

    sig_input = genesis_signature_input(document)
    signature = signing_key.sign(sig_input).signature
    signed_at = args.signed_at or (
        datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    )
    entry = {
        "signer_id": signer.signer_id,
        "fingerprint": fingerprint,
        "scheme_id": "ed25519",
        "signed_at": signed_at,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, sort_keys=True)
        f.write("\n")
    # Print the exact bytes being signed so an offline ceremony participant can
    # compare them against an independently computed value before trusting the file.
    print(f"signing_input_hex: {sig_input.hex()}")
    print(f"trust_domain_core_digest: {parsed.trust_domain_core_digest}")
    print(f"trust_domain_id: {parsed.trust_domain_id}")
    print(f"signer_id: {signer.signer_id}")
    print(f"fingerprint: {fingerprint}")
    print(f"detached signature written: {args.out}")


def cmd_trust_verify_genesis(args: argparse.Namespace) -> None:
    """Full genesis verification (TRUST-DOMAIN.md §3.5/§3.6); exit nonzero on invalid.
    Offline: reads only the named file."""
    from regista._trust_domain import verify_trust_genesis

    with open(args.file, encoding="utf-8") as f:
        document = json.load(f)
    report = verify_trust_genesis(document)  # raises RegistaError -> exit 1
    if getattr(args, "json", False):
        _dump_json(report.to_dict())
        return
    governance = report.root_governance
    # §3.7 report obligation: a human-facing report MUST display the mode when it
    # is solo or solo_effective. It is printed unconditionally here.
    print(f"root_governance.mode: {governance.mode}")
    print(f"threshold: {governance.threshold}")
    print(f"signer_count: {governance.signer_count}")
    print(f"trust_domain_core_digest: {report.trust_domain_core_digest}")
    print(f"trust_domain_id: {report.trust_domain_id}")
    print(f"signatures_verified: {report.signatures_verified}")
    print(f"extra_signatures: {report.extra_signatures}")
    print(f"independence: {governance.independence}")
    print(
        "custody_declared (unverified operator claims): "
        + ", ".join(governance.custody_declared)
    )
    print(
        "custody_declared_holders (unverified operator claims): "
        + ", ".join(report.custody_declared_holders_unverified)
    )
    print(f"countersignatures: {report.countersignatures_status} ({report.countersignature_count})")
    print(f"anchors: {report.anchors_status} ({report.anchor_count})")
    print("verdict: VALID")


def _load_genesis_document(path: str | None) -> dict[str, Any] | None:
    from ._trust_genesis_file import (
        load_trust_genesis_document,
        trust_genesis_path_from_env,
    )

    configured_path = path if path is not None else trust_genesis_path_from_env()
    return load_trust_genesis_document(configured_path)


def cmd_trust_rebuild_projection(args: argparse.Namespace) -> None:
    """Rebuild ``principal_keys`` from signed events alone (§5.9 rule 4).

    "If the table can be rebuilt on demand, the temptation to hand-fix a row
    disappears." ``--dry-run`` writes nothing and reports the diff; exit is non-zero
    when a dry run finds divergence, so it is usable as a check in a pipeline.
    """
    dsn, project, hmac_key_path = _require_config(args)
    genesis_document = _load_genesis_document(args.genesis)
    from regista._trust_projection import rebuild_projection

    sub = Regista(dsn, project, hmac_key_path)
    try:
        report = rebuild_projection(
            sub._mgr, project=project, genesis_document=genesis_document, dry_run=args.dry_run
        )
    except RegistaError as e:
        _handle_error(e, json_mode=getattr(args, "json", False))
        return
    finally:
        sub.close()

    if getattr(args, "json", False):
        _dump_json(report.to_dict())
    else:
        mode = "dry-run (nothing written)" if report.dry_run else "applied"
        print(f"rebuild-projection: {mode}")
        print(f"  project:                     {report.project}")
        print(f"  events replayed:             {report.events_replayed}")
        for transition, count in sorted(report.events_by_transition.items()):
            print(f"    {transition}: {count}")
        print(f"  v6 rows rebuilt:             {report.rows_rebuilt}")
        print(f"  legacy_unsourced preserved:  {report.legacy_unsourced_preserved}")
        print(f"  ordering basis:              {report.ordering_basis}")
        if report.skipped_events:
            print(f"  skipped events:              {len(report.skipped_events)}")
            for skipped in report.skipped_events:
                print(f"    {skipped.get('event_id')}: {skipped.get('reason')}")
        if report.differences:
            print(f"  DIVERGENCE: {len(report.differences)} row(s)")
            for diff in report.differences:
                fields = ", ".join(diff.fields)
                suffix = f" [{fields}]" if fields else ""
                print(f"    {diff.kind}: {diff.principal_id}/{diff.key_id}{suffix}")
        else:
            print("  divergence:                  none")
    # A dry run that found divergence is a failed check, not a successful report.
    if report.dry_run and report.differences:
        sys.exit(1)


def _synthesize_root_keyset_file(
    *, seed: bytes, public_key: bytes, principal_id: str, key_id: str
) -> str:
    """Write a 0600 single-entry Ed25519 actor key file for the root signer.

    ``write_trust_genesis`` consumes a :class:`KeySet` keyed by ``principal_id``
    (``_writer_key`` -> ``resolve_signing_key``), but the offline root key lives on
    disk as a bare 32-byte seed (the shape ``sign-genesis --key`` reads). This bridges
    the two: it wraps the seed in the key-file schema the KeySet loader expects, binds
    it to the operator-named root ``principal_id``, and returns the path. The caller
    MUST delete the file in a ``finally`` — it holds the root secret in cleartext, so it
    is created with owner-only permissions and never left behind.
    """
    import tempfile

    fd, path = tempfile.mkstemp(prefix="regista-trust-root-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "keys": [
                        {
                            "key_id": key_id,
                            "scheme": "ed25519",
                            "alg": "Ed25519",
                            "secret": base64.b64encode(seed).decode("ascii"),
                            "encoding": "base64",
                            "public_key": base64.b64encode(public_key).decode("ascii"),
                            "principal_id": principal_id,
                            "role": "actor",
                            "status": "active",
                        }
                    ]
                },
                f,
            )
    except BaseException:
        os.unlink(path)
        raise
    return path


def _warn_root_seed_not_removed(path: str, err: Exception) -> None:
    """Loudly report a failed unlink of the synthesized root-seed file.

    The file holds the estate ROOT SEED in cleartext. If it cannot be removed the
    operator must know *which* file was left behind and delete it by hand — this must
    never be swallowed silently (deepseek N1). Both a stderr banner and a structured
    error log are emitted so neither a human nor a log scraper misses it.
    """
    banner = (
        f"CRITICAL: could not remove the synthesized root-seed file {path!r} "
        f"({err}); it holds the estate ROOT SEED in cleartext. Delete it MANUALLY now."
    )
    print(banner, file=sys.stderr)
    try:  # pragma: no cover - logging must never mask the banner
        structlog.get_logger().error(
            "trust_init_log.root_seed_not_removed", path=path, error=str(err)
        )
    except Exception:
        pass


def _probe_trust_log_state(dsn: str, project: str) -> tuple[bool, bool]:
    """Probe the trust-log store: ``(schema_exists, already_initialized)``.

    Runs BEFORE any write, purely to drive the dry-run plan and the friendly
    idempotency refusal. It fails CLOSED with a named :class:`RegistaError`
    (``TRUST_LOG_STORE_UNAVAILABLE``) rather than leaking a raw psycopg traceback when
    (a) the DSN is unreachable — with a short ``connect_timeout`` so this fails fast
    instead of hanging on the pool's default 30s wait — or (b) the target namespace is
    occupied by a non-trust-log project (present schema, no ``events`` table →
    ``UndefinedTable``). Both violate the fail-closed CLI contract if surfaced raw
    (Opus NB-2 / deepseek N5).
    """
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.sql import SQL, Identifier

    from regista._connection import validate_project_name

    schema = validate_project_name(project)
    try:
        with psycopg.connect(
            dsn, connect_timeout=5, row_factory=dict_row, autocommit=True
        ) as conn:
            schema_row = conn.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
                [schema],
            ).fetchone()
            schema_exists = schema_row is not None
            already_initialized = False
            if schema_exists:
                conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
                try:
                    row = conn.execute(
                        "SELECT COUNT(*) AS n FROM events WHERE transition = %s",
                        ["trust_domain_established"],
                    ).fetchone()
                except psycopg.errors.UndefinedTable as exc:
                    raise RegistaError(
                        ErrorCode.TRUST_LOG_STORE_UNAVAILABLE,
                        f"schema {schema!r} exists but has no `events` table: the "
                        "namespace is occupied by something other than a trust-log "
                        "project. Refusing to initialize a trust log into a schema that "
                        "already belongs to a different project; choose an empty or "
                        "trust-log --project.",
                        {"reason": "schema_not_a_trust_log", "project": schema},
                    ) from exc
                already_initialized = bool(row and int(row["n"]) > 0)
            return schema_exists, already_initialized
    except RegistaError:
        raise
    except (psycopg.OperationalError, psycopg.Error) as exc:
        raise RegistaError(
            ErrorCode.TRUST_LOG_STORE_UNAVAILABLE,
            f"could not reach the trust-log store to probe schema {schema!r}: {exc}. "
            "Check --dsn / REGISTA_DSN and that the database is reachable.",
            {"reason": "store_unreachable", "project": schema},
        ) from exc


def cmd_trust_init_log(args: argparse.Namespace) -> None:
    """Write the estate-wide trust log's genesis ``trust_domain_established`` event.

    This is the one write that bootstraps a trust domain into a database: without it no
    key can be enrolled, because ``principal_keys`` is a projection of a *signed* trust
    log (TRUST-DOMAIN.md §5.2, §5.9). It takes an already-published, VALID genesis
    document and the root Ed25519 seed that signed it, and appends the genesis event
    into the trust-log project store, creating that store's schema if it does not exist.

    Fail-closed by construction: the document is verified before anything is written;
    the root key's fingerprint must be a genesis signer; the write is a single
    transaction inside ``write_trust_genesis`` (which itself refuses a second genesis,
    ``GENESIS_ALREADY_WRITTEN``); and ``--dry-run`` writes nothing. There is deliberately
    no ``--force``: re-initializing a trust log would fork its genesis, which is never a
    safe operation — an already-initialized log is a hard refusal, not an overwrite.

    The genesis event's ``actor_id`` (``--root-principal-id``) comes from the genesis's
    SIGNED ``initial_custody`` declared_holder, either by default (flag omitted) or by
    confirmation: WI-320 (a-prime) made an explicit ``--root-principal-id`` VERIFY-ONLY,
    so a value contradicting the custody entry for the supplied root key's fingerprint is
    refused (``ACTOR_SIGNER_MISMATCH``) instead of being written verbatim. Residual WI-320
    gap: ``declared_holder`` is signed but operator-declared, and the actor_id is still
    not cryptographically bound inside the signed event bytes.
    """
    import nacl.signing

    from regista._principal_keys import _compute_fingerprint
    from regista._principals import classify_principal_id
    from regista._trust_domain import (
        custody_for_root_fingerprint,
        parse_trust_genesis,
        verify_root_principal_binding,
        verify_trust_genesis,
    )
    from regista._trust_log_writer import write_trust_genesis

    json_mode = getattr(args, "json", False)

    dsn, project_cfg, _ = _resolve_config(args)
    if not dsn:
        print("Missing required config: --dsn or REGISTA_DSN", file=sys.stderr)
        sys.exit(2)

    # (1) Load + fully verify the genesis document. verify_trust_genesis raises
    # RegistaError on anything short of VALID, so an invalid document never reaches
    # a write path.
    genesis_document = _load_genesis_document(args.genesis)
    if genesis_document is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no genesis document: pass --genesis PATH or set "
            "REGISTA_TRUST_GENESIS_PATH",
            {"reason": "genesis_document_absent"},
        )
    verify_trust_genesis(genesis_document)  # RegistaError -> exit 1, no write
    doc = parse_trust_genesis(genesis_document)

    # (2) The provided root key must be one of the genesis signers. Derive its
    # fingerprint from the seed and match it against binding_core, so a wrong key is
    # refused here — before any schema is touched.
    seed = _read_ed25519_seed(args.key)
    public_key = bytes(nacl.signing.SigningKey(seed).verify_key)
    fingerprint = _compute_fingerprint(public_key, "ed25519")
    signer = doc.signer_by_fingerprint(fingerprint)
    if signer is None:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"the root key (fingerprint {fingerprint}) is not a signer in the "
            "genesis document's binding_core; refusing to initialize the trust log "
            "with a key the domain never committed to",
            {"reason": "root_key_not_a_genesis_signer", "fingerprint": fingerprint},
        )

    # The genesis actor is operator-DECLARED, not cryptographically bound to the signer
    # (WI-320 tracks closing that gap). Interim binding (Opus NB-1 / deepseek N2): when
    # --root-principal-id is omitted, DEFAULT it from the genesis's SIGNED initial_custody
    # declared_holder, so the common path binds the actor to a signed field rather than a
    # free operator choice. Only default when there is exactly ONE custody entry AND its
    # holder is already a canonical principal id — otherwise the operator must choose
    # explicitly rather than us guessing.
    #
    # WI-320 (a-prime): an EXPLICIT --root-principal-id is VERIFY-ONLY. It used to be
    # written into actor_id verbatim, so a genuine root seed could attribute the estate
    # genesis to any principal at all; it must now equal the declared_holder of the
    # custody entry for THIS root's fingerprint. The check itself lives in
    # _trust_domain.verify_root_principal_binding because write_trust_genesis enforces the
    # same binding at the durable boundary — this call is the early, actionable refusal.
    override = args.root_principal_id
    root_principal_id = override
    actor_source = "explicit_verified" if override is not None else "declared_holder"
    if root_principal_id is None:
        if len(doc.initial_custody) != 1:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"the genesis declares {len(doc.initial_custody)} custody entries, so "
                "the root actor cannot be inferred; pass --root-principal-id explicitly "
                "to name the genesis event's actor (it must equal the declared_holder "
                "this root signer's own custody entry names)",
                {
                    "reason": "custody_ambiguous_for_actor_default",
                    "custody_count": len(doc.initial_custody),
                },
            )
        # Keyed by THIS root's fingerprint rather than initial_custody[0]: provably the
        # same entry today (the guard above bounds the block to one entry and the
        # fingerprint is already proven to be a signer, so WI-292's 1:1 rule makes them
        # identical), but uniform with the verify-only path and correct if the
        # single-entry guard is ever relaxed.
        holder = custody_for_root_fingerprint(doc, fingerprint).declared_holder
        if not classify_principal_id(holder).canonical:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"the genesis's declared_holder {holder!r} is not a canonical "
                "kind:subject principal id, so it cannot be used as the root actor; "
                "pass --root-principal-id explicitly",
                {"reason": "declared_holder_not_canonical"},
            )
        root_principal_id = holder

    if not classify_principal_id(root_principal_id).canonical:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"--root-principal-id {root_principal_id!r} is not a canonical "
            "kind:subject principal id (TRUST-DOMAIN.md §2.1); the genesis event's "
            "actor is recorded permanently and must be well-formed",
            {"reason": "root_principal_id_not_canonical"},
        )
    if override is not None:
        verify_root_principal_binding(doc, root_principal_id, fingerprint)

    # The trust log is one estate-wide project whose first event is
    # trust_domain_established (§5.2). Its schema name is the document's SIGNED
    # project_name_hint ("regista_trust"). An explicit/ambient project (--project or
    # REGISTA_PROJECT) may only SELECT that same schema — never redirect the genesis
    # into a different one. REGISTA_PROJECT is commonly set for other commands, and
    # letting it silently override the signed hint could write the estate genesis into
    # the WRONG schema, inviting a second (different-doc) init elsewhere = two trust
    # domains for one estate (deepseek N3). So a mismatch is a hard refusal.
    hint = doc.trust_log.project_name_hint
    if project_cfg is not None and project_cfg != hint:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"the configured project {project_cfg!r} (--project or REGISTA_PROJECT) "
            f"differs from the genesis document's signed project_name_hint {hint!r}; "
            "refusing to write the estate genesis into a schema the document did not "
            f"name. Pass --project {hint} to match the document, or unset "
            "REGISTA_PROJECT.",
            {
                "reason": "project_precedence_conflict",
                "configured_project": project_cfg,
                "project_name_hint": hint,
            },
        )
    project = project_cfg or hint

    # A single --key seed can only supply ONE root signature. A k-of-n domain needs
    # detached signatures from multiple offline roots (the A-prime path), which this
    # CLI cannot collect. Refuse rather than write a genesis this key alone cannot
    # authorize.
    threshold = doc.initial_governance.threshold
    if threshold != 1:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            f"this genesis needs {threshold} root signatures (k-of-n), but "
            "`trust init-log` signs with a single --key. Build the "
            "trust_domain_established payload offline "
            "(build_trust_domain_established_payload), collect the detached root "
            "signatures, and use the A-prime writer path instead.",
            {"reason": "threshold_exceeds_single_key", "threshold": threshold},
        )

    # Probe the store: does the schema exist, and is a trust_domain_established event
    # already present? Used for the dry-run plan and for a friendly idempotency refusal
    # ahead of the writer's own authoritative guard. Fails closed with a named
    # RegistaError (never a raw traceback) if the store is unreachable or the namespace
    # is occupied by a non-trust-log project (Opus NB-2 / deepseek N5).
    schema_exists, already_initialized = _probe_trust_log_state(dsn, project)

    plan = {
        "action": "trust-init-log",
        "project": project,
        "trust_domain_id": doc.trust_domain_id,
        "project_instance_id": str(doc.trust_log.project_instance_id),
        "transition": "trust_domain_established",
        "root_principal_id": root_principal_id,
        "root_principal_source": actor_source,
        "root_signer_id": signer.signer_id,
        "root_fingerprint": fingerprint,
        "threshold": threshold,
        "schema_exists": schema_exists,
        "already_initialized": already_initialized,
    }

    # A real run refuses an already-initialized log (a second genesis would fork the
    # trust domain). --dry-run must REPORT that same would-outcome rather than claim
    # would_write:True — it probes the real state and mirrors the refusal (deepseek N4).
    refuse_reason = "genesis_already_written" if already_initialized else None

    if args.dry_run:
        would_write = refuse_reason is None
        plan["dry_run"] = True
        plan["would_write"] = would_write
        if refuse_reason is not None:
            plan["would_refuse_reason"] = refuse_reason
        if json_mode:
            _dump_json(plan)
        else:
            print("trust init-log: dry-run (nothing written)")
            print(f"  project (schema):        {project}")
            print(f"  schema exists:           {schema_exists}")
            print(f"  trust_domain_id:         {doc.trust_domain_id}")
            print(f"  project_instance_id:     {doc.trust_log.project_instance_id}")
            print("  event to write:          trust_domain_established")
            print(f"  root principal:          {root_principal_id} ({actor_source})")
            print(f"  root signer_id:          {signer.signer_id}")
            print(f"  root fingerprint:        {fingerprint}")
            print(f"  governance threshold:    {threshold}")
            print(f"  would write:             {would_write}")
            if refuse_reason is not None:
                print(f"  would refuse (reason):   {refuse_reason}")
        return

    if already_initialized:
        raise RegistaError(
            ErrorCode.GENESIS_ALREADY_WRITTEN,
            f"the trust log in schema {project!r} already carries a "
            "trust_domain_established event; refusing to re-initialize (a second "
            "genesis would fork the trust domain)",
            {"reason": "genesis_already_written", "project": project},
        )

    # (3)-(4) Prepare the trust-log project schema (create + migrate if new) and write
    # the genesis event. write_trust_genesis runs entirely inside one transaction and
    # re-verifies the document, re-checks the signer, and refuses a duplicate genesis,
    # so a failure at any step leaves no half-initialized log.
    key_file = _synthesize_root_keyset_file(
        seed=seed,
        public_key=public_key,
        principal_id=root_principal_id,
        key_id=f"k_{signer.signer_id}",
    )
    handle: Regista | None = None
    try:
        if schema_exists:
            handle = Regista(dsn, project, key_file)
        else:
            handle = Regista.create_project(dsn, project, key_file)
        event_id = write_trust_genesis(
            handle._mgr,
            keys=handle._keys,
            genesis_document=genesis_document,
            root_principal_id=root_principal_id,
        )
    finally:
        # Delete the cleartext root-seed file FIRST and independently of handle.close()
        # (deepseek N1): if close() raises — e.g. a broken pool after a write failure —
        # the seed must still be removed, and a failed unlink must be LOUD, never
        # silently swallowed. handle.close() runs in this inner finally so it still
        # happens even if the unlink (or its warning) raises.
        try:
            os.unlink(key_file)
        except OSError as unlink_err:
            _warn_root_seed_not_removed(key_file, unlink_err)
        finally:
            if handle is not None:
                handle.close()

    result = {
        "ok": True,
        "event_id": event_id,
        "transition": "trust_domain_established",
        "project": project,
        "trust_domain_id": doc.trust_domain_id,
        "project_instance_id": str(doc.trust_log.project_instance_id),
        "root_principal_id": root_principal_id,
    }
    if json_mode:
        _dump_json(result)
    else:
        print("trust init-log: trust_domain_established written")
        print(f"  event_id:                {event_id}")
        print(f"  project (schema):        {project}")
        print(f"  trust_domain_id:         {doc.trust_domain_id}")
        print(f"  project_instance_id:     {doc.trust_log.project_instance_id}")
        print(f"  root principal:          {root_principal_id}")


# --- WI-319 (2/3): `regista trust enroll` — the v6-native enrollment verifier -------
#
# Piece 1 (`trust init-log`) wrote the trust log's genesis; a key can now be enrolled
# INTO it. This is the VERIFIER/COMMIT counterpart of the client `signer` commands: it
# consumes the possession proof the enrollee produced and appends a signed
# `principal_key_enrolled` event through the trust-log-native writer
# (`_trust_log_writer.append_trust_log_event`), which is the ONLY writer the trust-log
# project accepts (its genesis is `trust_domain_established`, not an ordinary v6 epoch,
# so the `PrincipalLifecycle` commit path — which requires an accepted key-binding
# anchor — cannot append here). Enrolment is registrar-authorised: §5.5's
# `principal_key_enrolled` payload has no `root_signatures` slot (only rotation does),
# so a live `registrar_delegated` scoped to `principal_key_enrolled` is the authority.
#
# The ceremony is two phased because possession requires the ENROLLEE's private key,
# which the verifier must never hold:
#   1. `trust enroll --issue-challenge --principal <id> --public-key <b64>`
#        issues a fresh v2 possession challenge, persists it (unused), prints its JSON.
#   2. enrollee: `signer sign-possession --challenge <that JSON>` -> a possession proof.
#   3. `trust enroll --principal <id> --public-key <b64> --proof-file <proof>
#        --key <registrar seed> --registrar-principal-id <id>`
#        verifies the proof, consumes the challenge, and appends the signed event.
# `rebuild-projection` then materialises the key into `principal_keys` (§5.9).


def _iso_micro_z(value: datetime) -> str:
    """The microsecond-UTC ``...Z`` timestamp form the §5.5 parsers require."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _enroll_public_key(value: str) -> bytes:
    """Decode a base64 Ed25519 public key argument to its 32 raw bytes, fail-closed."""
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--public-key must be a base64-encoded 32-byte Ed25519 public key",
            {"reason": "public_key_not_base64"},
        ) from exc
    if len(raw) != 32:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"--public-key must decode to 32 bytes, got {len(raw)}",
            {"reason": "public_key_wrong_length", "length": len(raw)},
        )
    return raw


def _enroll_require_canonical(principal_id: str) -> str:
    """Return the canonical principal kind, or refuse a non-canonical id (§2.1)."""
    from regista._principals import classify_principal_id

    classification = classify_principal_id(principal_id)
    if not classification.canonical or classification.kind is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"{principal_id!r} is not a canonical kind:subject principal id "
            "(TRUST-DOMAIN.md §2.1)",
            {"reason": "principal_id_not_canonical", "principal_id": principal_id},
        )
    return classification.kind


def _enroll_resolve_target(args: argparse.Namespace) -> tuple[str, dict[str, Any], Any, str]:
    """Resolve (dsn, genesis_document, parsed genesis, project) for an enroll command.

    Mirrors `trust init-log`'s precedence: the trust-log schema is the document's SIGNED
    ``project_name_hint``; an explicit/ambient project may only SELECT that same schema,
    never redirect enrolment into a foreign one.
    """
    from regista._trust_domain import parse_trust_genesis

    dsn, project_cfg, _ = _resolve_config(args)
    if not dsn:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "missing required config: --dsn or REGISTA_DSN",
            {"reason": "dsn_absent"},
        )
    genesis_document = _load_genesis_document(args.genesis)
    if genesis_document is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no genesis document: pass --genesis PATH or set REGISTA_TRUST_GENESIS_PATH",
            {"reason": "genesis_document_absent"},
        )
    doc = parse_trust_genesis(genesis_document)
    hint = doc.trust_log.project_name_hint
    if project_cfg is not None and project_cfg != hint:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"the configured project {project_cfg!r} differs from the genesis "
            f"document's signed project_name_hint {hint!r}; pass --project {hint} or "
            "unset REGISTA_PROJECT",
            {"reason": "project_precedence_conflict"},
        )
    return dsn, genesis_document, doc, (project_cfg or hint)


def _enroll_require_initialized(dsn: str, project: str) -> None:
    """Refuse cleanly if the trust log's genesis has not been written yet."""
    _schema_exists, already_initialized = _probe_trust_log_state(dsn, project)
    if not already_initialized:
        raise RegistaError(
            ErrorCode.TRUST_LOG_STORE_UNAVAILABLE,
            f"the trust log in schema {project!r} has no trust_domain_established "
            "genesis; run `regista trust init-log` before enrolling a key into it",
            {"reason": "trust_log_not_initialized", "project": project},
        )


def _enroll_persist_challenge(conn: Any, challenge: Any) -> None:
    """Insert the (operation, unused possession-challenge) rows the ceremony needs.

    A ``lifecycle_challenges`` row FK-references ``lifecycle_operations`` (migration 043),
    so a placeholder operation is inserted first. The trust-log writer's possession
    admission (`_verify_possession_evidence`) reads the challenge row back by
    ``challenge_id``; the operation carries no lifecycle semantics here — it exists only
    to satisfy the foreign key.
    """
    conn.execute(
        "INSERT INTO lifecycle_operations "
        "(operation_id, idempotency_key, operation_type, state, project, principal_id, "
        "principal_kind, actor_id, reason, requested_authority, policy_version, "
        "digest_value, digest_algorithm, digest_version, protected_options, "
        "created_at, expires_at) "
        "VALUES (%s, %s, 'enrollment', 'awaiting_proof', %s, %s, %s, %s, "
        "'trust-log enrollment', 'registrar', 'trust-log', %s, 'sha-256', '1', "
        "'{}'::jsonb, %s, %s) "
        "ON CONFLICT (operation_id) DO NOTHING",
        [
            uuid.UUID(challenge.operation_id),
            "trust-enroll-" + challenge.challenge_id,
            challenge.project,
            challenge.principal_id,
            challenge.principal_kind,
            challenge.principal_id,
            challenge.operation_digest,
            challenge.issued_at,
            challenge.expires_at,
        ],
    )
    conn.execute(
        "INSERT INTO lifecycle_challenges "
        "(challenge_id, operation_id, operation_digest, project, principal_id, "
        "fingerprint, scheme, verifier_nonce, issued_at, expires_at, used, kind, "
        "trust_domain_id, enrollment_request_digest, proof_signature) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, false, 'possession', %s, %s, NULL)",
        [
            uuid.UUID(challenge.challenge_id),
            uuid.UUID(challenge.operation_id),
            challenge.operation_digest,
            challenge.project,
            challenge.principal_id,
            challenge.fingerprint,
            challenge.scheme,
            challenge.verifier_nonce,
            challenge.issued_at,
            challenge.expires_at,
            uuid.UUID(challenge.trust_domain_id),
            challenge.enrollment_request_digest,
        ],
    )


class _EnrollChallenge:
    """The issued possession challenge, carrying the enrollee kind alongside §5.5 fields."""

    def __init__(self, *, challenge: Any, principal_kind: str) -> None:
        self.v2 = challenge
        self.principal_kind = principal_kind

    def __getattr__(self, name: str) -> Any:  # delegate §5.5 fields to the v2 object
        return getattr(self.v2, name)


def _issue_enroll_challenge(
    args: argparse.Namespace, *, dsn: str, project: str, doc: Any, json_mode: bool
) -> None:
    import secrets

    from regista._connection import ConnectionManager
    from regista._principal_keys import _compute_fingerprint
    from regista._trust_log import PossessionChallengeV2, enrollment_request_digest

    principal_kind = _enroll_require_canonical(args.principal)
    public_key = _enroll_public_key(args.public_key)
    fingerprint = _compute_fingerprint(public_key, "ed25519")
    now = datetime.now(UTC)
    ttl_minutes = args.ttl_minutes if args.ttl_minutes is not None else 30
    challenge = PossessionChallengeV2(
        challenge_id=str(uuid.uuid4()),
        operation_id=str(uuid.uuid4()),
        # No durable lifecycle operation backs a trust-log enrolment; the digest is a
        # well-formed placeholder (the possession binding rests on the challenge fields
        # and the verifier_nonce, not on this value).
        operation_digest="sha256:" + "0" * 64,
        project=project,
        trust_domain_id=doc.trust_domain_id,
        principal_id=args.principal,
        fingerprint=fingerprint,
        scheme="ed25519",
        verifier_nonce=secrets.token_bytes(32).hex(),
        # Bind BOTH the principal and the key fingerprint being enrolled (N5, PR #58):
        # the digest is stored on the challenge and echoed in the possession proof, which
        # the verifier checks for equality — folding the fingerprint in makes the proof
        # inseparable from the exact key it enrols (defence in depth). Nothing recomputes
        # this from principal_id alone, so widening the bound request is safe.
        enrollment_request_digest=enrollment_request_digest(
            {"principal_id": args.principal, "fingerprint": fingerprint}
        ),
        issued_at=_iso_micro_z(now),
        expires_at=_iso_micro_z(now + timedelta(minutes=ttl_minutes)),
    )
    wrapped = _EnrollChallenge(challenge=challenge, principal_kind=principal_kind)

    if args.dry_run:
        plan = {
            "action": "trust-enroll-issue-challenge",
            "dry_run": True,
            "would_write": True,
            "project": project,
            "principal_id": args.principal,
            "fingerprint": fingerprint,
            "trust_domain_id": doc.trust_domain_id,
            "challenge_id": challenge.challenge_id,
        }
        if json_mode:
            _dump_json(plan)
        else:
            print("trust enroll --issue-challenge: dry-run (nothing written)")
            print(f"  project:          {project}")
            print(f"  principal:        {args.principal}")
            print(f"  fingerprint:      {fingerprint}")
            print(f"  challenge_id:     {challenge.challenge_id}")
        return

    mgr = ConnectionManager(dsn, project)
    try:
        mgr.open()
        with mgr.transaction() as conn:
            _enroll_persist_challenge(conn, wrapped)
    finally:
        mgr.close()

    if json_mode:
        # The challenge object itself, in the exact shape `signer sign-possession`
        # consumes (§5.5 v2, including trust_domain_id + enrollment_request_digest).
        _dump_json(challenge.to_dict())
    else:
        print(f"Issued possession challenge {challenge.challenge_id} for {args.principal}:")
        print("  hand the JSON below to the enrollee for `regista signer sign-possession`:")
        print(json.dumps(challenge.to_dict(), indent=2, sort_keys=True))


def _load_stored_challenge(conn: Any, challenge_id: str) -> Any:
    from regista._trust_log import PossessionChallengeV2

    try:
        cid = uuid.UUID(challenge_id)
    except (ValueError, AttributeError) as exc:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"the proof names a malformed challenge_id {challenge_id!r}",
            {"reason": "challenge_id_malformed"},
        ) from exc
    row = conn.execute(
        "SELECT challenge_id, operation_id, operation_digest, project, principal_id, "
        "fingerprint, scheme, verifier_nonce, issued_at, expires_at, used, "
        "trust_domain_id, enrollment_request_digest, proof_signature "
        "FROM lifecycle_challenges WHERE challenge_id = %s AND kind = 'possession'",
        [cid],
    ).fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            f"no possession challenge {challenge_id!r} is on record; issue one with "
            "`regista trust enroll --issue-challenge` first",
            {"reason": "possession_challenge_not_found", "challenge_id": challenge_id},
        )
    challenge = PossessionChallengeV2(
        challenge_id=str(row["challenge_id"]),
        operation_id=str(row["operation_id"]),
        operation_digest=row["operation_digest"],
        project=row["project"],
        trust_domain_id=str(row["trust_domain_id"]),
        principal_id=row["principal_id"],
        fingerprint=row["fingerprint"],
        scheme=row["scheme"],
        verifier_nonce=row["verifier_nonce"],
        enrollment_request_digest=row["enrollment_request_digest"],
        issued_at=_iso_micro_z(row["issued_at"]),
        expires_at=_iso_micro_z(row["expires_at"]),
    )
    return challenge, bool(row["used"])


def _commit_enroll(
    args: argparse.Namespace,
    *,
    dsn: str,
    genesis_document: dict[str, Any],
    doc: Any,
    project: str,
    json_mode: bool,
) -> None:
    import nacl.signing

    from regista._connection import ConnectionManager
    from regista._principal_keys import _compute_fingerprint, principal_entity_id
    from regista._trust_log import (
        POSSESSION_DOMAIN_V2,
        verify_possession_proof_v2,
    )
    from regista._trust_log_writer import append_trust_log_event, replay_trust_state

    principal_kind = _enroll_require_canonical(args.principal)
    public_key = _enroll_public_key(args.public_key)
    fingerprint = _compute_fingerprint(public_key, "ed25519")
    _enroll_require_canonical(args.registrar_principal_id)

    # The authorising key is the registrar's delegated key. Derive its fingerprint from
    # the supplied seed so a wrong key is refused against the replayed delegation.
    seed = _read_ed25519_seed(args.key)
    registrar_public = bytes(nacl.signing.SigningKey(seed).verify_key)
    registrar_fingerprint = _compute_fingerprint(registrar_public, "ed25519")

    # Read the possession proof the enrollee produced (`signer sign-possession`).
    proof_text = args.proof
    if proof_text is None and args.proof_file:
        try:
            proof_text = open(args.proof_file, encoding="utf-8").read()
        except OSError as exc:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"cannot read --proof-file: {exc}",
                {"reason": "proof_file_unreadable"},
            ) from exc
    if proof_text is None:
        proof_text = sys.stdin.read()
    if not proof_text or not proof_text.strip():
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no possession proof provided (use --proof, --proof-file, or stdin)",
            {"reason": "possession_proof_absent"},
        )
    try:
        proof_data = json.loads(proof_text)
        proof_challenge_id = proof_data["challenge_id"]
        proof_signature = base64.b64decode(proof_data["signature"], validate=True)
    except (ValueError, KeyError, TypeError) as exc:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "the possession proof is not the JSON `signer sign-possession` emits "
            "(needs challenge_id + base64 signature)",
            {"reason": "possession_proof_malformed"},
        ) from exc

    _enroll_require_initialized(dsn, project)

    mgr = ConnectionManager(dsn, project)
    plan_only = args.dry_run
    try:
        mgr.open()
        with mgr.transaction() as conn:
            state = replay_trust_state(conn, genesis_document)
            challenge, already_used = _load_stored_challenge(conn, proof_challenge_id)

        # The challenge must be for THIS principal and key, or the proof binds nothing.
        if challenge.principal_id != args.principal:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"the challenge names principal {challenge.principal_id!r}, not "
                f"{args.principal!r}",
                {"reason": "possession_challenge_principal_mismatch"},
            )
        if challenge.fingerprint != fingerprint:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "the challenge was issued for a different key than --public-key",
                {"reason": "possession_challenge_fingerprint_mismatch"},
            )

        # Refuse an expired challenge cleanly BEFORE the single-use consume. Without
        # this, an expired challenge would be burned by the UPDATE and only then
        # rejected by the writer's admission check — losing the challenge for a retry
        # and reporting a downstream reason. `challenge.expires_at` is the always-µs-Z
        # form `_load_stored_challenge` emits.
        challenge_expires_at = datetime.strptime(
            challenge.expires_at, "%Y-%m-%dT%H:%M:%S.%fZ"
        ).replace(tzinfo=UTC)
        if datetime.now(UTC) >= challenge_expires_at:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"possession challenge {challenge.challenge_id!r} has expired "
                f"(expired at {challenge.expires_at}); issue a fresh challenge to enrol",
                {
                    "reason": "possession_challenge_expired",
                    "challenge_id": challenge.challenge_id,
                },
            )

        # Resolve the registrar's live delegation from the replayed trust state and
        # verify the supplied key IS the delegated key. `append_trust_log_event` re-runs
        # the full authority check; this front-loads it so an unauthorised key is
        # refused BEFORE the challenge is consumed.
        entry = state.registrars.get(args.registrar_principal_id)
        if entry is None or entry.revoked:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"{args.registrar_principal_id!r} has no live registrar delegation in "
                "the trust log; only a delegated registrar (or root, out of scope here) "
                "may authorise an enrolment",
                {"reason": "no_live_registrar_delegation"},
            )
        if _compute_fingerprint(entry.public_key, "ed25519") != registrar_fingerprint:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                "the --key seed is not the registrar's delegated key",
                {"reason": "authorizing_key_not_the_delegated_key"},
            )
        if "principal_key_enrolled" not in entry.scopes:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"the registrar delegation does not scope principal_key_enrolled "
                f"(scopes: {sorted(entry.scopes)})",
                {"reason": "enrolment_out_of_registrar_scope"},
            )

        # Idempotency: if this principal already has an ACTIVE key with these exact
        # public bytes, enrolling again is a clean no-op — never a duplicate or a fork.
        for (p_id, k_id), pub in state.principal_public_keys.items():
            if (
                p_id == args.principal
                and pub == public_key
                and state.principal_key_status.get((p_id, k_id)) == "active"
            ):
                result = {
                    "ok": True,
                    "already_enrolled": True,
                    "project": project,
                    "principal_id": args.principal,
                    "key_id": k_id,
                    "fingerprint": fingerprint,
                }
                if json_mode:
                    _dump_json(result)
                else:
                    print(
                        f"Principal {args.principal} already has this key enrolled and "
                        f"active (key_id {k_id}); nothing to do."
                    )
                return

        # Enrolment BINDS a principal's key where there is none. If the principal already
        # has a live key whose bytes differ from the one offered, this is NOT an
        # enrolment — it is a key change, which §5.6 handles as a ROTATION with dual
        # authorization (the outgoing key's signature). Silently writing a second
        # `principal_key_enrolled` would let the projection supersede the incumbent key
        # WITHOUT that dual proof, so a single registrar could seize any principal's
        # identity. Refuse and direct the operator to `trust rotate`. (The same-key
        # short-circuit above keeps re-enrolling an already-active key an idempotent
        # no-op.) The writer enforces the same invariant so a direct append cannot
        # bypass this.
        for (p_id, k_id), pub in state.principal_public_keys.items():
            if (
                p_id == args.principal
                and pub != public_key
                and state.principal_key_status.get((p_id, k_id)) == "active"
            ):
                raise RegistaError(
                    ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                    f"principal {args.principal!r} already has an active key "
                    f"(key_id {k_id}); enrolment binds a key where there is none. "
                    "Changing an existing key is a rotation (§5.6) — use `regista trust "
                    "rotate`, which requires the outgoing key's dual authorization.",
                    {
                        "reason": "enrollment_key_already_present",
                        "principal_id": args.principal,
                        "active_key_id": k_id,
                    },
                )

        key_id = "pk_" + uuid.uuid4().hex[:16]
        payload: dict[str, Any] = {
            "type": "regista.key-enrollment",
            "version": 1,
            "trust_domain_id": doc.trust_domain_id,
            "principal_id": args.principal,
            "principal_kind": principal_kind,
            "key_id": key_id,
            "scheme_id": "ed25519",
            "public_key": base64.b64encode(public_key).decode("ascii"),
            "fingerprint": fingerprint,
            "not_before": _iso_micro_z(datetime.now(UTC)),
            "not_after": None,
            "possession_proof": {
                "domain": POSSESSION_DOMAIN_V2,
                "challenge_id": challenge.challenge_id,
                "verifier_nonce": challenge.verifier_nonce,
                "enrollment_request_digest": challenge.enrollment_request_digest,
                "signature": base64.b64encode(proof_signature).decode("ascii"),
            },
            "authorized_by": {
                "authority": "registrar",
                "principal_id": args.registrar_principal_id,
                "key_id": entry.key_id,
                "delegation_event_hash": entry.delegated_event_hash,
            },
            "custody": {
                "declared_backend": args.custody_backend or "operator",
                "declared_policy_ref": args.policy_ref or "policy://trust/enrollment/v1",
            },
            "supersedes_key_id": None,
        }

        # Verify the possession proof against the stored challenge BEFORE consuming it —
        # a wrong or absent proof is refused here, with nothing written and the challenge
        # left unburned. (`append_trust_log_event` verifies it again against the durable
        # consumed row; this is the fail-closed pre-check.)
        verify_possession_proof_v2(payload, challenge)

        plan = {
            "action": "trust-enroll",
            "project": project,
            "trust_domain_id": doc.trust_domain_id,
            "transition": "principal_key_enrolled",
            "principal_id": args.principal,
            "principal_kind": principal_kind,
            "key_id": key_id,
            "fingerprint": fingerprint,
            "authority": "registrar",
            "registrar_principal_id": args.registrar_principal_id,
            "delegation_event_hash": entry.delegated_event_hash,
            "challenge_id": challenge.challenge_id,
        }

        if plan_only:
            plan["dry_run"] = True
            plan["would_write"] = True
            if already_used:
                # A real run would refuse a re-used challenge; mirror that in the plan.
                plan["would_write"] = False
                plan["would_refuse_reason"] = "possession_challenge_already_used"
            if json_mode:
                _dump_json(plan)
            else:
                print("trust enroll: dry-run (nothing written)")
                print(f"  project:                 {project}")
                print(f"  principal:               {args.principal}")
                print(f"  key_id:                  {key_id}")
                print(f"  fingerprint:             {fingerprint}")
                print(f"  authority:               registrar {args.registrar_principal_id}")
                print(f"  delegation_event_hash:   {entry.delegated_event_hash}")
                print(f"  would write:             {plan.get('would_write')}")
                if plan.get("would_refuse_reason"):
                    print(f"  would refuse (reason):   {plan['would_refuse_reason']}")
            return

        # Consume the challenge single-use (used=false -> true, recording the verified
        # proof signature). The conditional UPDATE is the atomic single-use guard: a
        # second concurrent (or replayed) commit finds zero rows and is refused, so the
        # same challenge can never back two enrolments.
        with mgr.transaction() as conn:
            consumed = conn.execute(
                "UPDATE lifecycle_challenges SET used = true, proof_signature = %s "
                "WHERE challenge_id = %s AND used = false",
                [
                    base64.b64encode(proof_signature).decode("ascii"),
                    uuid.UUID(challenge.challenge_id),
                ],
            ).rowcount
        if consumed != 1:
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"possession challenge {challenge.challenge_id!r} was already consumed; "
                "issue a fresh challenge to re-enrol",
                {"reason": "possession_challenge_already_used"},
            )
    finally:
        mgr.close()

    # Append the signed principal_key_enrolled event through the trust-log-native writer,
    # authorised as the registrar. The writer re-verifies possession (against the now
    # durably-consumed challenge) and the registrar authority inside its own single
    # transaction, so a failure here appends nothing — never a partial enrolment.
    key_file = _synthesize_root_keyset_file(
        seed=seed,
        public_key=registrar_public,
        principal_id=args.registrar_principal_id,
        key_id=entry.key_id,
    )
    handle: Regista | None = None
    try:
        handle = Regista(dsn, project, key_file)
        event_id = append_trust_log_event(
            handle._mgr,
            keys=handle._keys,
            genesis_document=genesis_document,
            transition="principal_key_enrolled",
            payload=payload,
            entity_kind="principal",
            entity_id=principal_entity_id(args.principal),
            principal_id=args.registrar_principal_id,
            authority="registrar",
        )
    finally:
        try:
            os.unlink(key_file)
        except OSError as unlink_err:
            _warn_root_seed_not_removed(key_file, unlink_err)
        finally:
            if handle is not None:
                handle.close()

    result = {
        "ok": True,
        "already_enrolled": False,
        "event_id": event_id,
        "transition": "principal_key_enrolled",
        "project": project,
        "trust_domain_id": doc.trust_domain_id,
        "principal_id": args.principal,
        "key_id": key_id,
        "fingerprint": fingerprint,
        "authority": "registrar",
        "registrar_principal_id": args.registrar_principal_id,
    }
    if json_mode:
        _dump_json(result)
    else:
        print("trust enroll: principal_key_enrolled written")
        print(f"  event_id:                {event_id}")
        print(f"  project (schema):        {project}")
        print(f"  principal:               {args.principal}")
        print(f"  key_id:                  {key_id}")
        print(f"  fingerprint:             {fingerprint}")
        print(f"  authority:               registrar {args.registrar_principal_id}")
        print("  run `regista trust rebuild-projection` to materialise principal_keys")


def cmd_trust_enroll(args: argparse.Namespace) -> None:
    """Enrol a principal's Ed25519 key into the estate trust log (§5.5).

    Authority model: this is a REGISTRAR-authorised path, distinct from the
    ordinary-project ``PrincipalLifecycle`` ceremony (which gates on a distinct
    approver). A live registrar's delegation — granted under root authority — IS the
    authority to enrol, so there is deliberately NO separate approval step here; the
    delegation carries it. The enrollee's possession proof is still required, and the
    projection is still materialised from the signed event by ``rebuild-projection``,
    never written directly.

    Two modes. ``--issue-challenge`` issues a fresh v2 possession challenge for a
    principal + public key and prints it (phase 1). The default mode consumes the
    possession proof the enrollee produced from that challenge and appends the signed
    ``principal_key_enrolled`` event under a registrar's delegated authority (phase 2).
    Fail-closed throughout: the trust log must be initialised; the authorising key must
    be a live registrar's delegated key; the possession proof must verify; the challenge
    is single-use and must be unexpired; re-enrolling an already-active key is a clean
    no-op; and enrolling a DIFFERENT key over a principal that already has a live key is
    refused — that is a §5.6 rotation (use ``trust rotate``), not an enrolment.
    """
    json_mode = getattr(args, "json", False)
    dsn, genesis_document, doc, project = _enroll_resolve_target(args)

    if args.issue_challenge:
        _enroll_require_initialized(dsn, project)
        _issue_enroll_challenge(args, dsn=dsn, project=project, doc=doc, json_mode=json_mode)
        return

    for name in ("key", "registrar_principal_id"):
        if getattr(args, name, None) is None:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"--{name.replace('_', '-')} is required to commit an enrolment "
                "(omit it only with --issue-challenge)",
                {"reason": "missing_commit_argument", "argument": name},
            )
    _commit_enroll(
        args,
        dsn=dsn,
        genesis_document=genesis_document,
        doc=doc,
        project=project,
        json_mode=json_mode,
    )


# --- WI-321 (3/3): `regista trust delegate-registrar` — root delegates registrar power -
#
# The missing middle link of the v6 provisioning chain: root-genesis (`trust init-log`)
# -> ROOT delegates a registrar (THIS command) -> the registrar enrols host keys
# (`trust enroll`). Enrolment is registrar-authorised, so until a root-signed
# ``registrar_delegated`` event exists in the trust log nothing can be enrolled. Before
# this command that event was only reachable from test-internal helpers
# (``make_registrar_delegation_payload`` + ``append_trust_log_event``); this wires the
# existing root-authorised write to an operator CLI. It DOES touch the database.


def _default_registrar_scopes() -> list[str]:
    """The default registrar scope set: the key-lifecycle administration transitions.

    A registrar's authority is lifecycle administration only (§5.4); it never extends to
    writing work-item events (that is §5.12's separate action-delegation credential).
    The default grants the three key-lifecycle transitions — enrol, rotate, revoke — the
    common per-host provisioning set. ``principal_registered`` is left out of the default
    (grant it explicitly with ``--scope`` when a registrar must also register principals).
    """
    from regista._trust_log import (
        PRINCIPAL_KEY_ENROLLED,
        PRINCIPAL_KEY_REVOKED,
        PRINCIPAL_KEY_ROTATED,
    )

    return [PRINCIPAL_KEY_ENROLLED, PRINCIPAL_KEY_ROTATED, PRINCIPAL_KEY_REVOKED]


def _parse_scope_args(raw_scopes: list[str] | None) -> list[str]:
    """Normalise repeatable/comma-joined ``--scope`` values to a de-duplicated list.

    Accepts ``--scope a --scope b`` and ``--scope a,b`` (and any mix). Order is
    preserved and duplicates are collapsed; membership in the registrar scope set is
    validated downstream by ``parse_registrar_delegated`` so a bad scope is a named
    refusal, not a silent drop. Returns the lifecycle default when nothing is given.
    """
    if not raw_scopes:
        return _default_registrar_scopes()
    out: list[str] = []
    for chunk in raw_scopes:
        for token in chunk.split(","):
            scope = token.strip()
            if scope and scope not in out:
                out.append(scope)
    if not out:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--scope was given but resolved to no transitions",
            {"reason": "empty_scope_set"},
        )
    return out


def _resolve_trust_root_actor(
    doc: TrustGenesisDocument, override: str | None, root_fingerprint: str
) -> tuple[str, str]:
    """Resolve the root actor principal id for a root-authorised trust-log write.

    Mirrors ``trust init-log`` exactly: when ``--root-principal-id`` is omitted, default
    it from the genesis's SIGNED ``initial_custody`` declared_holder — but only when there
    is exactly ONE custody entry whose holder is already a canonical principal id.
    Otherwise the operator must name it explicitly. An explicit value is VERIFY-ONLY
    (WI-320 (a-prime)): it must equal the declared_holder of the custody entry belonging
    to *root_fingerprint*, the signer whose seed authorises this write. The actor remains an
    operator-DECLARED identity, not one cryptographically bound to the root signature
    (the residual WI-320 gap), and it still has to be a well-formed canonical id because
    it is recorded permanently.
    """
    from regista._principals import classify_principal_id
    from regista._trust_domain import (
        custody_for_root_fingerprint,
        verify_root_principal_binding,
    )

    root_principal_id = override
    source = "explicit_verified" if override is not None else "declared_holder"
    if root_principal_id is None:
        if len(doc.initial_custody) != 1:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"the genesis declares {len(doc.initial_custody)} custody entries, so "
                "the root actor cannot be inferred; pass --root-principal-id explicitly "
                "to name the delegation event's actor (it must equal the declared_holder "
                "this root signer's own custody entry names)",
                {
                    "reason": "custody_ambiguous_for_actor_default",
                    "custody_count": len(doc.initial_custody),
                },
            )
        # Fingerprint-keyed for the same reason as `init-log`'s defaulting path.
        holder = custody_for_root_fingerprint(doc, root_fingerprint).declared_holder
        if not classify_principal_id(holder).canonical:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"the genesis's declared_holder {holder!r} is not a canonical "
                "kind:subject principal id, so it cannot be used as the root actor; "
                "pass --root-principal-id explicitly",
                {"reason": "declared_holder_not_canonical"},
            )
        root_principal_id = holder

    if not classify_principal_id(root_principal_id).canonical:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"--root-principal-id {root_principal_id!r} is not a canonical "
            "kind:subject principal id (TRUST-DOMAIN.md §2.1); the event's actor is "
            "recorded permanently and must be well-formed",
            {"reason": "root_principal_id_not_canonical"},
        )
    if override is not None:
        verify_root_principal_binding(doc, root_principal_id, root_fingerprint)
    return root_principal_id, source


def cmd_trust_delegate_registrar(args: argparse.Namespace) -> None:
    """Delegate registrar power under ROOT authority (§5.4 ``registrar_delegated``).

    Root genesis (``trust init-log``) is written; this command lets the estate ROOT grant
    a principal the scoped, expiring authority to administer key lifecycle — the authority
    ``trust enroll`` then requires. It takes the ROOT authorising seed (whose fingerprint
    must be a genesis signer), the registrar's principal id + granted public key/key_id,
    the scope of transitions the registrar may authorise, and a validity window, builds
    the root-signed ``registrar_delegated`` payload, and appends it through the trust-log
    writer in one transaction.

    Fail-closed by construction: the trust log must be initialised (else
    ``TRUST_LOG_STORE_UNAVAILABLE``); the root key must be a current genesis signer (else
    ``ACTOR_SIGNER_MISMATCH``); a k-of-n genesis (threshold > 1) is refused because a
    single ``--key`` seed cannot meet the threshold (like ``init-log``); the payload is
    parsed and root-threshold-verified BEFORE any write; ``--dry-run`` writes nothing; a
    live registrar delegation for the same principal is a clean no-op when byte-identical
    and a named refusal (revoke first) when its terms differ, so a re-delegation never
    silently forks; and the cleartext root seed synthesised for the writer is removed in a
    ``finally`` with a loud warning if the unlink fails. No authority check is weakened —
    the writer re-runs the full root-threshold verification inside its own transaction, and
    the no-live-fork invariant is re-enforced at the durable writer AND at replay (not only
    in this CLI pre-check), so a direct writer call or two concurrent runs cannot fork it.

    Idempotency caveat (N1): the default ``--not-before``/``--not-after`` anchor to
    call-time ``now()`` at microsecond resolution. A byte-identical re-run WITHOUT pinned
    windows therefore differs from the incumbent and is refused
    ``registrar_already_delegated_live`` (fail-safe, not a no-op). Pin BOTH bounds to make
    a re-run idempotent.
    """
    import nacl.signing

    from regista._connection import ConnectionManager
    from regista._principal_keys import _compute_fingerprint
    from regista._trust_log import (
        REGISTRAR_MAX_VALIDITY,
        parse_registrar_delegated,
        refuse_registrar_delegating_registrar,
        root_signature_input,
        verify_root_threshold,
    )
    from regista._trust_log_writer import append_trust_log_event, replay_trust_state

    json_mode = getattr(args, "json", False)
    dsn, genesis_document, doc, project = _enroll_resolve_target(args)

    # (1) Validate the registrar identity + granted key material. The public key is the
    # artifact the enrol verifier will check the registrar's own signatures against.
    _enroll_require_canonical(args.registrar_principal_id)
    registrar_public = _enroll_public_key(args.registrar_public_key)
    registrar_fingerprint = _compute_fingerprint(registrar_public, "ed25519")
    scopes = _parse_scope_args(args.scope)

    # (2) The authorising key must be a CURRENT root signer. Derive its fingerprint from
    # the seed and match it against binding_core — a wrong key is refused before any write.
    # These genesis-intrinsic checks (signer, threshold) run BEFORE the store probe, exactly
    # as `init-log` does: they depend only on the document, so a wrong key or a k-of-n
    # domain is refused deterministically whether or not the log has been initialised.
    seed = _read_ed25519_seed(args.key)
    root_public = bytes(nacl.signing.SigningKey(seed).verify_key)
    root_fingerprint = _compute_fingerprint(root_public, "ed25519")
    signer = doc.signer_by_fingerprint(root_fingerprint)
    if signer is None:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"the root key (fingerprint {root_fingerprint}) is not a signer in the "
            "genesis document's binding_core; refusing to sign a registrar delegation "
            "with a key the domain never committed to",
            {"reason": "root_key_not_a_genesis_signer", "fingerprint": root_fingerprint},
        )

    # (3) A single --key seed supplies exactly ONE root signature. A k-of-n domain needs
    # detached signatures from multiple offline roots, which this CLI cannot collect.
    # Refuse rather than write a delegation this key alone cannot authorise (like init-log).
    threshold = doc.initial_governance.threshold
    if threshold != 1:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            f"this trust domain needs {threshold} root signatures (k-of-n), but "
            "`trust delegate-registrar` signs with a single --key. Build the "
            "registrar_delegated payload offline, collect the detached root signatures, "
            "and append it via the trust-log writer instead.",
            {"reason": "threshold_exceeds_single_key", "threshold": threshold},
        )

    # (4) The trust log must already carry its genesis, else there is nothing to delegate
    # into. Reuses the shared TRUST_LOG_STORE_UNAVAILABLE refusal.
    _enroll_require_initialized(dsn, project)

    root_principal_id, actor_source = _resolve_trust_root_actor(
        doc, args.root_principal_id, root_fingerprint
    )

    # (5) Validity window: anchored to CALL-TIME now() (never a fixed date — the trust
    # fixtures were bitten by exactly that time-bomb). Defaults: opens an hour back to
    # absorb clock skew so the registrar can act immediately, closes a year ahead
    # (comfortably inside the §5.4 400-day bound). Explicit --not-before/--not-after
    # override; their format is validated by parse_registrar_delegated below.
    now = datetime.now(UTC)
    not_before = args.not_before or _iso_micro_z(now - timedelta(hours=1))
    not_after = args.not_after or _iso_micro_z(now + timedelta(days=365))

    max_operations = args.max_operations

    # (6) Assemble the §5.4 payload and sign it under ROOT authority: each detached root
    # signature covers root_signature_input(payload) (the framed authorization core).
    payload: dict[str, Any] = {
        "type": "regista.registrar-delegation",
        "version": 1,
        "trust_domain_id": doc.trust_domain_id,
        "registrar_principal_id": args.registrar_principal_id,
        "key_id": args.registrar_key_id,
        "scheme_id": "ed25519",
        "public_key": base64.b64encode(registrar_public).decode("ascii"),
        "fingerprint": registrar_fingerprint,
        "scopes": scopes,
        "not_before": not_before,
        "not_after": not_after,
        "max_operations": max_operations,
        "root_signatures": [],
    }
    signature = nacl.signing.SigningKey(seed).sign(root_signature_input(payload)).signature
    payload["root_signatures"] = [
        {
            "signer_id": signer.signer_id,
            "fingerprint": root_fingerprint,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
    ]

    # (7) Verify-before-write: parse the payload (structural §5.4 rules — scope set,
    # mandatory bounded not_after, window ordering, key material/fingerprint agreement,
    # max_operations) so a malformed delegation is refused here with a named error, before
    # the store is touched. Raises RegistaError, surfaced by main()'s handler.
    parsed = parse_registrar_delegated(payload)

    # (8) Replay the live trust state for the root-threshold pre-check and the
    # re-delegation / registrar-cannot-delegate guards. append_trust_log_event re-runs the
    # authority check in-transaction; this front-loads it so dry-run reports the true
    # outcome and a bad delegation is refused before the write path.
    mgr = ConnectionManager(dsn, project)
    already_delegated_noop = False
    existing_hash: str | None = None
    try:
        mgr.open()
        with mgr.transaction() as conn:
            state = replay_trust_state(conn, genesis_document)
    finally:
        mgr.close()

    # Root-threshold pre-check against the CURRENT governance/root keys (mirrors the
    # writer). A signature that does not verify, or a fingerprint no longer in the signer
    # set, is refused here rather than deep inside the writer.
    verify_root_threshold(payload, state.governance, state.root_public_keys)

    live_registrars = {
        pid for pid, entry in state.registrars.items() if not entry.revoked
    }
    existing = state.registrars.get(args.registrar_principal_id)
    if existing is not None and not existing.revoked:
        identical = (
            existing.public_key == registrar_public
            and existing.key_id == args.registrar_key_id
            and existing.scopes == frozenset(scopes)
            and existing.max_operations == max_operations
            and existing.not_before == parsed.not_before
            and existing.not_after == parsed.not_after
        )
        existing_hash = existing.delegated_event_hash
        if identical:
            already_delegated_noop = True
        else:
            # A live delegation with DIFFERENT terms already exists. Appending a second
            # would fork the credential (which term set is authoritative?). §5.4 forbids
            # naming a principal that is already a registrar; the legitimate re-delegation
            # path is to revoke the existing delegation first, then delegate afresh. Refuse
            # cleanly and point the operator at that flow rather than forking silently.
            raise RegistaError(
                ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
                f"{args.registrar_principal_id!r} already has a live registrar "
                f"delegation (event {existing.delegated_event_hash}) whose terms differ "
                "from the requested ones; a registrar cannot be re-delegated while live "
                "(§5.4). Revoke the existing delegation (registrar_revoked) first, then "
                "delegate again.",
                {
                    "reason": "registrar_already_delegated_live",
                    "registrar_principal_id": args.registrar_principal_id,
                    "existing_delegation_event_hash": existing.delegated_event_hash,
                },
            )
    else:
        # Structural §5.4 guard: registrar_delegated must not name a principal that is
        # already a LIVE registrar. A revoked prior delegation does not count (revoke →
        # re-delegate is the supported window/key refresh path), so only live ids are
        # passed. In the not-live case this passes trivially; belt-and-braces.
        refuse_registrar_delegating_registrar(
            parsed, existing_registrar_principal_ids=sorted(live_registrars)
        )

    window_days = (parsed.not_after - parsed.not_before).days
    plan = {
        "action": "trust-delegate-registrar",
        "project": project,
        "trust_domain_id": doc.trust_domain_id,
        "transition": "registrar_delegated",
        "registrar_principal_id": args.registrar_principal_id,
        "registrar_key_id": args.registrar_key_id,
        "registrar_fingerprint": registrar_fingerprint,
        "scopes": scopes,
        "not_before": not_before,
        "not_after": not_after,
        "validity_days": window_days,
        "max_operations": max_operations,
        "max_validity_days": REGISTRAR_MAX_VALIDITY.days,
        "authority": "root",
        "root_principal_id": root_principal_id,
        "root_principal_source": actor_source,
        "root_signer_id": signer.signer_id,
        "root_fingerprint": root_fingerprint,
    }

    if args.dry_run:
        would_write = not already_delegated_noop
        plan["dry_run"] = True
        plan["would_write"] = would_write
        if already_delegated_noop:
            plan["already_delegated"] = True
            plan["existing_delegation_event_hash"] = existing_hash
        if json_mode:
            _dump_json(plan)
        else:
            print("trust delegate-registrar: dry-run (nothing written)")
            print(f"  project:                 {project}")
            print(f"  trust_domain_id:         {doc.trust_domain_id}")
            print(f"  registrar principal:     {args.registrar_principal_id}")
            print(f"  registrar key_id:        {args.registrar_key_id}")
            print(f"  registrar fingerprint:   {registrar_fingerprint}")
            print(f"  scopes:                  {', '.join(scopes)}")
            print(f"  validity window:         {not_before} .. {not_after} ({window_days}d)")
            print(f"  max operations:          {max_operations}")
            print(f"  authority:               root {root_principal_id} ({actor_source})")
            print(f"  root signer_id:          {signer.signer_id}")
            print(f"  would write:             {would_write}")
            if already_delegated_noop:
                print(f"  already delegated:       {existing_hash} (no-op)")
        return

    # Idempotent no-op: an identical live delegation already exists. Re-running is safe and
    # writes nothing rather than forking the credential.
    if already_delegated_noop:
        result = {
            "ok": True,
            "already_delegated": True,
            "transition": "registrar_delegated",
            "project": project,
            "trust_domain_id": doc.trust_domain_id,
            "registrar_principal_id": args.registrar_principal_id,
            "registrar_key_id": args.registrar_key_id,
            "delegation_event_hash": existing_hash,
        }
        if json_mode:
            _dump_json(result)
        else:
            print(
                f"Registrar {args.registrar_principal_id} already has this exact "
                f"delegation ({existing_hash}); nothing to do."
            )
        return

    # (9) Append the root-signed registrar_delegated event through the trust-log-native
    # writer. It re-verifies the root threshold and refuses on any authority failure inside
    # its own single transaction, so a failure here appends nothing — never a partial
    # delegation. The synthesized key file binds the root seed to the root actor principal
    # (the writer resolves the signing key by principal_id) and is deleted in the finally.
    key_file = _synthesize_root_keyset_file(
        seed=seed,
        public_key=root_public,
        principal_id=root_principal_id,
        key_id=f"k_{signer.signer_id}",
    )
    handle: Regista | None = None
    try:
        handle = Regista(dsn, project, key_file)
        event_id = append_trust_log_event(
            handle._mgr,
            keys=handle._keys,
            genesis_document=genesis_document,
            transition="registrar_delegated",
            payload=payload,
            entity_kind="trust_domain",
            entity_id=uuid.UUID(doc.trust_domain_id),
            principal_id=root_principal_id,
            authority="root",
        )
    finally:
        try:
            os.unlink(key_file)
        except OSError as unlink_err:
            _warn_root_seed_not_removed(key_file, unlink_err)
        finally:
            if handle is not None:
                handle.close()

    result = {
        "ok": True,
        "already_delegated": False,
        "event_id": event_id,
        "transition": "registrar_delegated",
        "project": project,
        "trust_domain_id": doc.trust_domain_id,
        "registrar_principal_id": args.registrar_principal_id,
        "registrar_key_id": args.registrar_key_id,
        "registrar_fingerprint": registrar_fingerprint,
        "scopes": scopes,
        "not_before": not_before,
        "not_after": not_after,
        "max_operations": max_operations,
        "authority": "root",
        "root_principal_id": root_principal_id,
    }
    if json_mode:
        _dump_json(result)
    else:
        print("trust delegate-registrar: registrar_delegated written")
        print(f"  event_id:                {event_id}")
        print(f"  project (schema):        {project}")
        print(f"  registrar principal:     {args.registrar_principal_id}")
        print(f"  registrar key_id:        {args.registrar_key_id}")
        print(f"  scopes:                  {', '.join(scopes)}")
        print(f"  validity window:         {not_before} .. {not_after}")
        print(f"  authority:               root {root_principal_id}")
        print("  the registrar may now authorise `regista trust enroll`")


# --- WI-330: the signed estate cutover catalog (TRUST-DOMAIN.md §4.3) -------------
#
# agent-suite's cutover runbook §5.4 step 4 says "produce and publish the signed estate
# cutover catalog through regista's documented catalog command ... do not hand-author
# catalog JSON". No such command existed: the artifact was fully specified (§4.3) and
# byte-frozen (tests/vectors/v6/estate-catalog.json) with nothing able to emit it.
#
# Naming. `trust catalog` produces and signs; `trust sign-catalog` adds one more root
# signature offline (the airgapped k-of-n leg); `trust verify-catalog` is the
# fail-closed counterpart the runbook's step 5 ("re-fetch the publication through an
# independent checkout and verify its signatures, catalog fields, and referenced
# heads") runs. `catalog` matches the runbook's own wording and §4.4's
# `trust publish --kind catalog`; `sign-catalog`/`verify-catalog` match the existing
# `trust sign-genesis`/`trust verify-genesis` verbs. ARCHITECTURE-0.6.0.md:942-943 makes
# produce-and-sign ONE step and publish the NEXT one, which is why signing is folded
# into `catalog` and nothing in this file touches git or a network.
#
# PUBLISHING IS NOT DONE HERE. §4.4's `regista trust publish --kind catalog --input
# <signed.json> --repo <clone>` is a separate, keyless command that does not yet exist
# in this codebase. `trust catalog` writes the exact canonical publication bytes and
# prints the §4.2 path they belong at; committing them to the publication clone stays
# an operator step until that command lands.


def _write_canonical_atomic(path: str, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically, or leave the previous file untouched.

    A plain ``open(path, "wb")`` truncates first, so a crash or a full disk mid-write
    leaves a torn catalog at the path an operator is about to publish — and with
    ``--force`` it destroys the previous, valid artifact before knowing the new one is
    good (WI-330 review N-a). The sequence here is the durable one: write a sibling
    temp file, flush, ``fsync`` it, read it back and compare, then ``os.replace`` (which
    is atomic within a filesystem), then ``fsync`` the directory so the rename itself
    survives a power loss. Any failure unlinks the temp file and re-raises, leaving the
    original in place.
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        with open(tmp, "rb") as handle:
            if handle.read() != data:
                raise RegistaError(
                    ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID,
                    f"the bytes written to {tmp} do not read back identically; the "
                    "artifact was NOT published to the target path",
                    {"reason": "atomic_write_readback_mismatch", "path": path},
                )
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # Durably record the rename. Best-effort: not every platform lets you fsync a
    # directory, and failing the whole ceremony over that would be worse than the
    # (already-atomic) rename not being flushed yet.
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def _precheck_out_path(path: str, *, force: bool, dry_run: bool) -> None:
    """Refuse an unusable ``--out`` BEFORE any store walk or key read.

    A missing parent directory or a directory passed as ``--out`` used to surface as a
    raw ``IsADirectoryError``/``FileNotFoundError`` traceback after the whole ceremony
    had run (WI-330 review N-c). All three refusals are named, and they happen first so
    an offline ceremony discovers the typo before the keys come out.
    """
    if os.path.isdir(path):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"--out {path!r} is a directory; name the catalog file to write",
            {"reason": "out_path_is_directory", "path": path},
        )
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not os.path.isdir(directory):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"--out {path!r} names a file in {directory!r}, which does not exist",
            {"reason": "out_parent_missing", "path": path, "parent": directory},
        )
    if not os.access(directory, os.W_OK):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"--out {path!r} is not writable: {directory!r} denies writes",
            {"reason": "out_parent_not_writable", "path": path, "parent": directory},
        )
    if os.path.exists(path) and not force and not dry_run:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"refusing to overwrite existing catalog file {path}; choose another "
            "--out path or pass --force. A catalog is published immutably, so silently "
            "replacing one on disk is how the wrong bytes reach the channel.",
            {"reason": "output_exists", "path": path},
        )


def _load_json_document(path: str, what: str, reason_prefix: str) -> Any:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"cannot read {what} {path!r}: {exc}",
            {"reason": f"{reason_prefix}_unreadable", "path": path},
        ) from exc
    except (ValueError, UnicodeError) as exc:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"{what} {path!r} is not valid JSON: {exc}",
            {"reason": f"{reason_prefix}_invalid_json", "path": path},
        ) from exc


def _resolve_root_authority(
    args: argparse.Namespace, genesis_document: Mapping[str, Any]
) -> RootAuthorityState:
    """Derive the root authority: genesis, advanced by the verified trust log if given.

    THE trust-log input design (WI-330 review FR2-1). regista's trust log is a
    PostgreSQL project and §4.2 publishes no trust-log export, so "present the log"
    means naming the schema that holds it: ``--trust-log-dsn`` (defaulting to the
    global ``--dsn``/``REGISTA_DSN``) plus ``--trust-log-project``. When it is
    presented, ``verify_trust_log_chain`` replays it from the pinned genesis under full
    verification and the authority is the replayed state — the same walk the in-store
    verifier uses.

    When it is NOT presented — the offline auditor's case, with only the §4.2
    publication in hand — the authority is genesis. That is not a weaker check: genesis
    is the chain's root, so it is the state of a domain with zero rotation events, and a
    checkpoint claiming any other signer set is REFUSED by name with instructions to
    present the log. An unproven rotation is never believed, and there is deliberately
    no operator channel for root public keys.
    """
    from regista._connection import ConnectionManager
    from regista._estate_catalog import genesis_root_authority, trust_log_root_authority

    project = getattr(args, "trust_log_project", None)
    if project is None:
        return genesis_root_authority(genesis_document)
    dsn = getattr(args, "trust_log_dsn", None) or (args.dsn or os.environ.get("REGISTA_DSN"))
    if not dsn:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--trust-log-project needs a DSN: pass --trust-log-dsn, or --dsn/REGISTA_DSN",
            {"reason": "trust_log_dsn_absent", "trust_log_project": project},
        )
    _genesis_require_trust_log(dsn, project)
    mgr = ConnectionManager(dsn, project)
    try:
        mgr.open()
        # NOT `SET TRANSACTION READ ONLY`: the verified walk takes `SELECT ... FOR
        # SHARE` row locks, which PostgreSQL forbids in a read-only transaction. Every
        # statement on this path is a SELECT.
        with mgr.transaction() as conn:
            return trust_log_root_authority(conn, genesis_document)
    finally:
        mgr.close()


def _catalog_signers(
    key_paths: list[str], *, authority: RootAuthorityState
) -> list[tuple[bytes, str, str]]:
    """Resolve ``--key`` seeds to (seed, signer_id, fingerprint), authorised.

    Each key must be in the root set DERIVED from genesis and the verified trust log —
    never in a set the checkpoint declares about itself (WI-330 review FR2-1). After a
    rotation a removed root cannot sign and a rotated-in root can, and both facts come
    from the log rather than from the document being signed.

    ``signer_id`` is the genesis name for an original root; a root rotated in later has
    no genesis entry, so its fingerprint is used as its own label. Verification applies
    the same rule (``authority.signer_ids.get`` returns ``None`` and the signer_id check
    is skipped), so the two sides agree by construction.
    """
    import nacl.signing

    from regista._principal_keys import _compute_fingerprint

    resolved: list[tuple[bytes, str, str]] = []
    seen: set[str] = set()
    for path in key_paths:
        seed = _read_ed25519_seed(path)
        public = bytes(nacl.signing.SigningKey(seed).verify_key)
        fingerprint = _compute_fingerprint(public, "ed25519")
        if fingerprint not in authority.signer_fingerprints:
            raise RegistaError(
                ErrorCode.ACTOR_SIGNER_MISMATCH,
                f"the key at {path} (fingerprint {fingerprint}) is not in the root set "
                f"derived from {authority.source}; a root the verified trust chain does "
                "not make current may not sign a cutover catalog",
                {
                    "reason": "root_key_not_active",
                    "fingerprint": fingerprint,
                    "authority_source": authority.source,
                    "derived_actives": list(authority.signer_fingerprints),
                },
            )
        if fingerprint in seen:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"--key {path} repeats a signer already supplied ({fingerprint}); two "
                "signatures by one root cannot raise the distinct-signer count",
                {"reason": "duplicate_signing_key", "fingerprint": fingerprint},
            )
        seen.add(fingerprint)
        resolved.append(
            (seed, authority.signer_ids.get(fingerprint, fingerprint), fingerprint)
        )
    return resolved


def cmd_trust_catalog(args: argparse.Namespace) -> None:
    """Produce and sign the estate cutover catalog (TRUST-DOMAIN.md §4.3).

    The ordered ceremony, every step of which happens BEFORE anything is written:

      1. resolve config; refuse without a DSN; refuse an unusable ``--out``
      2. load and fully verify the pinned trust-genesis document
      3. parse the operator's measurements file and expected-estate manifest
      4. walk the LIVE trust log: reconcile the PUBLISHED checkpoint against it AND
         derive the root authority (signer set, threshold, public keys) from it
      5. authenticate that checkpoint against the DERIVED authority, never its own claims
      6. resolve every ``--key`` against that derived root set
      7. DERIVE each project's facts from its signed events and cross-check them
         against the posture rows AND the approved preflight numbers
      8. cross-check any re-measurable legacy store against the recorded numbers
      9. decide completeness against the expected-estate manifest
     10. build, validate, sign, re-verify, and write canonical JCS bytes atomically

    ``--dry-run`` performs 1-9, prints the digest the real run would produce, and
    writes nothing. The digest covers the core only (signatures are excluded from the
    signed bytes), so the dry run reports the *same* digest the signed artifact carries
    — it is not an approximation.
    """
    from regista._connection import ConnectionManager
    from regista._estate_catalog import (
        CATALOG_STATUS_PARTIAL,
        CatalogProject,
        build_estate_catalog,
        estate_catalog_digest,
        measure_frozen_legacy,
        measure_new_epoch,
        parse_catalog_inputs,
        parse_estate_manifest,
        sign_estate_catalog,
        trust_log_root_authority,
        verify_estate_catalog,
        verify_published_checkpoint,
    )
    from regista._genesis_open import load_published_checkpoint
    from regista._jcs import canonicalize
    from regista._trust_domain import parse_trust_genesis, verify_trust_genesis

    json_mode = getattr(args, "json", False)

    # (1) Config. Every project in the catalog is a schema on this one DSN, which is
    # the estate's actual deployment shape; a per-project DSN would mean putting
    # connection strings in a file the runbook forbids holding secret values.
    dsn, _, _ = _resolve_config(args)
    if not dsn:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "missing required config: --dsn or REGISTA_DSN",
            {"reason": "dsn_absent"},
        )
    _precheck_out_path(args.out, force=args.force, dry_run=args.dry_run)

    # (2) The pinned genesis document, fully verified.
    genesis_document = _load_genesis_document(args.genesis)
    if genesis_document is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no trust-genesis document: pass --genesis PATH or set "
            "REGISTA_TRUST_GENESIS_PATH. The catalog states which trust domain the "
            "cutover happened in; without the pinned document there is nothing to "
            "bind it to.",
            {"reason": "genesis_document_absent"},
        )
    verify_trust_genesis(genesis_document)
    doc = parse_trust_genesis(genesis_document)
    trust_project = args.trust_project or doc.trust_log.project_name_hint

    # Validate the two operator-supplied literals BEFORE any store read. Both are
    # validated again inside `build_estate_catalog`, but that happens after the trust-log
    # walk and every project measurement — and an offline ceremony discovers a typo in
    # `--created-at` with the keys already back in the safe. Same reasoning as
    # `trust sign-genesis`'s early `--signed-at` check.
    if args.created_at is not None and _MICROSECOND_UTC_RE.fullmatch(args.created_at) is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--created-at must be a UTC Z timestamp with EXACTLY six fractional digits "
            "(YYYY-MM-DDTHH:MM:SS.ffffffZ)",
            {"reason": "created_at_malformed", "created_at": args.created_at},
        )
    if args.prev_commit is not None and (
        len(args.prev_commit) != 40
        or any(char not in "0123456789abcdef" for char in args.prev_commit)
    ):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--prev-commit must be a full lowercase 40-hex git commit",
            {"reason": "prev_commit_malformed", "prev_commit": args.prev_commit},
        )

    # A published checkpoint is the only acceptable source for
    # trust_log_checkpoint_digest: a local observation is not a checkpoint
    # (`_genesis_open.TRUST_LOG_OBSERVATION_TYPE`), and binding one would put an
    # unobserved claim in a field that reads as published.
    publication_args = (args.trust_publication_repo, args.trust_publication_commit)
    if any(value is None for value in publication_args):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--trust-checkpoint requires both --trust-publication-repo and the "
            "out-of-band --trust-publication-commit pin",
            {"reason": "checkpoint_publication_pin_absent"},
        )

    # (3) The operator's measurements and expected estate.
    inputs = parse_catalog_inputs(
        _load_json_document(args.inputs, "--inputs", "inputs_file")
    )
    manifest_domain, expected_ids = parse_estate_manifest(
        _load_json_document(args.expected_estate, "--expected-estate", "expected_estate_file")
    )
    if manifest_domain != doc.trust_domain_id:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_UNVERIFIED,
            f"--expected-estate names trust domain {manifest_domain!r} but the pinned "
            f"genesis is {doc.trust_domain_id!r}",
            {
                "reason": "expected_estate_trust_domain_mismatch",
                "manifest": manifest_domain,
                "genesis": doc.trust_domain_id,
            },
        )
    for entry in inputs:
        if trust_project in (entry.project, entry.legacy_project):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"{entry.project!r} is the trust log's own schema. The cutover catalog "
                "lists ORDINARY projects; the trust log's state is bound through "
                "trust_log_checkpoint_digest, not as a projects[] entry.",
                {"reason": "input_project_is_trust_log", "project": entry.project},
            )

    # (4) The published checkpoint, reconciled against the LIVE trust log. This is the
    # same routine `genesis init` uses, so the digest the catalog binds is the same
    # value every project's bootstrap acceptance already binds.
    _genesis_require_trust_log(dsn, trust_project)
    trust_mgr = ConnectionManager(dsn, trust_project)
    try:
        trust_mgr.open()
        # NOT `SET TRANSACTION READ ONLY`: the verified walk takes `SELECT ... FOR
        # SHARE` row locks, which PostgreSQL forbids in a read-only transaction. Every
        # statement on this path is a SELECT.
        with trust_mgr.transaction() as conn:
            published = load_published_checkpoint(
                args.trust_checkpoint,
                conn,
                genesis_document,
                publication_repo=args.trust_publication_repo,
                publication_commit=args.trust_publication_commit,
            )
            # The root authority, from the SAME verified walk. This is the only source
            # of "who may sign" (WI-330 review FR2-1): the checkpoint's own
            # active_root_fingerprints are a claim to be reconciled, never the answer.
            authority = trust_log_root_authority(conn, genesis_document)
    finally:
        trust_mgr.close()

    # (5) Authenticate the same checkpoint the way an OFFLINE auditor will, against the
    # authority derived above, so the set and threshold the build signs under are the
    # ones `verify-catalog` will independently derive.
    checkpoint_bytes = _read_catalog_bytes(args.trust_checkpoint, "trust-checkpoint")
    checkpoint = verify_published_checkpoint(
        checkpoint_bytes,
        genesis_document=genesis_document,
        authority=authority,
    )
    threshold = authority.threshold

    # (6) Every --key must be a CURRENTLY ACTIVE root, per the derived authority.
    signers = _catalog_signers(list(args.key), authority=authority)
    if len(signers) < threshold and not args.incomplete_signatures:
        raise RegistaError(
            ErrorCode.TRUST_LOG_AUTHORITY_INVALID,
            f"this trust domain needs {threshold} root signatures but {len(signers)} "
            f"--key seed(s) were supplied. Either pass every root's seed to this "
            "invocation, or pass --incomplete-signatures to write a partially signed "
            "catalog and finish it on each remaining root's own host with "
            "`regista trust sign-catalog`. An under-signed catalog never verifies, so "
            "it is not written by accident.",
            {
                "reason": "root_threshold_not_met",
                "threshold": threshold,
                "keys_supplied": len(signers),
            },
        )

    # (7)/(8) Per project: DERIVE the epoch facts from signed events, cross-check them
    # against the approved preflight numbers, and cross-check the recorded legacy
    # numbers against the frozen store whenever it is still reachable.
    projects: list[CatalogProject] = []
    legacy_sources: dict[str, str] = {}
    for entry in inputs:
        target_mgr = ConnectionManager(dsn, entry.project)
        try:
            target_mgr.open()
            with target_mgr.transaction() as conn:
                conn.execute("SET TRANSACTION READ ONLY")
                measured = measure_new_epoch(conn, project=entry.project)
        finally:
            target_mgr.close()
        if measured.trust_domain_id != doc.trust_domain_id:
            raise RegistaError(
                ErrorCode.ESTATE_CATALOG_UNVERIFIED,
                f"project {entry.project!r} was opened in trust domain "
                f"{measured.trust_domain_id} but the pinned genesis document is "
                f"{doc.trust_domain_id}; a project from another domain does not belong "
                "in this catalog",
                {
                    "reason": "project_trust_domain_mismatch",
                    "project": entry.project,
                    "project_trust_domain_id": measured.trust_domain_id,
                    "catalog_trust_domain_id": doc.trust_domain_id,
                },
            )
        # ARCHITECTURE-0.6.0.md:802-810: "Confirm the head/count equal the approved
        # preflight result." The command derived these from event bytes; the operator
        # recorded them at preflight. Two independent witnesses, and a disagreement
        # stops the ceremony rather than being resolved in favour of either.
        if (
            measured.new_epoch_head_event_hash != entry.expected_new_epoch_head_event_hash
            or measured.event_count != entry.expected_new_epoch_event_count
        ):
            raise RegistaError(
                ErrorCode.ESTATE_CATALOG_UNVERIFIED,
                f"project {entry.project!r} does not match the approved preflight "
                "result; the catalog is not signed over either value",
                {
                    "reason": "new_epoch_preflight_mismatch",
                    "project": entry.project,
                    "expected": {
                        "new_epoch_head_event_hash": (
                            entry.expected_new_epoch_head_event_hash
                        ),
                        "event_count": entry.expected_new_epoch_event_count,
                    },
                    "derived": {
                        "new_epoch_head_event_hash": measured.new_epoch_head_event_hash,
                        "event_count": measured.event_count,
                    },
                },
            )

        legacy_head = entry.legacy_head_event_hash
        legacy_count = entry.legacy_event_count
        scheme_counts = entry.scheme_counts
        source = "operator_recorded"
        if entry.legacy_project is not None:
            legacy_mgr = ConnectionManager(dsn, entry.legacy_project)
            try:
                legacy_mgr.open()
                with legacy_mgr.transaction() as conn:
                    conn.execute("SET TRANSACTION READ ONLY")
                    legacy = measure_frozen_legacy(conn, project=entry.legacy_project)
            finally:
                legacy_mgr.close()
            if entry.has_recorded_legacy_facts:
                recorded = (legacy_head, legacy_count, dict(scheme_counts or {}))
                observed = (
                    legacy.head_event_hash,
                    legacy.event_count,
                    dict(legacy.scheme_counts),
                )
                if recorded != observed:
                    raise RegistaError(
                        ErrorCode.ESTATE_CATALOG_UNVERIFIED,
                        f"the recorded legacy measurements for {entry.project!r} "
                        f"disagree with schema {entry.legacy_project!r} as measured "
                        "now; one of the two is wrong and the catalog is not signed "
                        "over either",
                        {
                            "reason": "legacy_measurement_mismatch",
                            "project": entry.project,
                            "legacy_project": entry.legacy_project,
                            "recorded": {
                                "legacy_head_event_hash": legacy_head,
                                "legacy_event_count": legacy_count,
                                "scheme_counts": dict(scheme_counts or {}),
                            },
                            "measured": {
                                "legacy_head_event_hash": legacy.head_event_hash,
                                "legacy_event_count": legacy.event_count,
                                "scheme_counts": dict(legacy.scheme_counts),
                            },
                        },
                    )
                source = "operator_recorded_and_measured"
            else:
                source = "measured"
            legacy_head = legacy.head_event_hash
            legacy_count = legacy.event_count
            scheme_counts = legacy.scheme_counts
        assert legacy_head is not None and legacy_count is not None
        assert scheme_counts is not None
        legacy_sources[entry.project_name_hint] = source
        projects.append(
            CatalogProject(
                project_instance_id=measured.project_instance_id,
                project_name_hint=entry.project_name_hint,
                cutover_event_hash=measured.cutover_event_hash,
                legacy_head_event_hash=legacy_head,
                legacy_event_count=legacy_count,
                scheme_counts=scheme_counts,
                new_epoch_head_event_hash=measured.new_epoch_head_event_hash,
            )
        )

    # (9) Completeness. RECONCILIATION.md:682-684 — the COMPLETE estate catalog is the
    # artifact that says the ceremony succeeded, and "a partial catalog says
    # catalog_status: partial and is ceremony failure, not success".
    covered = {entry.project_instance_id for entry in projects}
    unexpected = sorted(covered - set(expected_ids))
    if unexpected:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_UNVERIFIED,
            "the measured projects include project_instance_id(s) absent from "
            "--expected-estate; that is not an incomplete ceremony, it is the wrong "
            "estate",
            {
                "reason": "catalog_project_not_in_expected_estate",
                "unexpected": unexpected,
            },
        )
    missing = sorted(set(expected_ids) - covered)
    catalog_status = None
    if missing:
        if not args.allow_partial:
            raise RegistaError(
                ErrorCode.ESTATE_CATALOG_UNVERIFIED,
                f"--expected-estate lists {len(expected_ids)} project(s) but only "
                f"{len(covered)} are covered; {len(missing)} would be MISSING. A "
                "partial catalog is a ceremony FAILURE (RECONCILIATION.md:682-684), so "
                "it is not produced unless --allow-partial says so explicitly, and it "
                "is then stamped catalog_status: partial inside the signed bytes.",
                {
                    "reason": "catalog_would_be_partial",
                    "expected": len(expected_ids),
                    "covered": len(covered),
                    "missing_project_instance_ids": missing,
                },
            )
        catalog_status = CATALOG_STATUS_PARTIAL

    created_at = args.created_at or (datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z")
    document = build_estate_catalog(
        trust_domain_id=doc.trust_domain_id,
        trust_domain_core_digest=doc.trust_domain_core_digest,
        root_governance={
            "mode": checkpoint.governance.mode,
            "threshold": checkpoint.governance.threshold,
            "signer_count": checkpoint.governance.signer_count,
        },
        projects=projects,
        trust_log_checkpoint_digest=checkpoint.document_digest,
        created_at=created_at,
        prev_commit=args.prev_commit,
        catalog_status=catalog_status,
    )
    digest = estate_catalog_digest(document)
    # §4.2's layout. Printed, never written to: choosing the path inside the
    # publication clone is `trust publish`'s job, and this command never touches git.
    stamp = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y%m%dT%H%M%SZ")
    publication_path = f"catalogs/{stamp}-{document['catalog_kind']}.json"

    plan: dict[str, Any] = {
        "action": "trust-catalog",
        "catalog_kind": document["catalog_kind"],
        "catalog_status": catalog_status or "complete",
        "trust_domain_id": doc.trust_domain_id,
        "trust_domain_core_digest": doc.trust_domain_core_digest,
        "root_governance": {
            "mode": checkpoint.governance.mode,
            "threshold": checkpoint.governance.threshold,
            "signer_count": checkpoint.governance.signer_count,
        },
        "root_authority": authority.to_dict(),
        "active_root_fingerprints": list(authority.signer_fingerprints),
        "trust_log_checkpoint_digest": checkpoint.document_digest,
        "trust_log_checkpoint_seq": checkpoint.checkpoint_seq,
        "trust_log_checkpoint_source": published.source,
        "trust_log_checkpoint_signatures_verified": checkpoint.signatures_verified,
        "trust_log_publication_commit": published.publication_commit,
        "created_at": created_at,
        "prev_commit": args.prev_commit,
        "estate_catalog_digest": digest,
        "project_count": len(projects),
        "expected_project_count": len(expected_ids),
        "missing_project_instance_ids": missing,
        "projects": [entry.as_document_member() for entry in sorted(
            projects, key=lambda item: item.project_name_hint
        )],
        "legacy_measurement_sources": legacy_sources,
        "epoch_facts_source": "recomputed_from_signed_events",
        "root_signer_ids": [signer_id for _, signer_id, _ in signers],
        "root_fingerprints": [fingerprint for _, _, fingerprint in signers],
        "signatures_to_apply": len(signers),
        "out": args.out,
        "recommended_publication_path": publication_path,
        "publication": "operator_step",
    }

    if args.dry_run:
        plan["dry_run"] = True
        plan["would_write"] = args.out
        if json_mode:
            _dump_json(plan)
        else:
            print("trust catalog: dry-run (nothing written)")
            _print_catalog_plan(plan)
        return

    signed: dict[str, Any] = dict(document)
    for seed, signer_id, fingerprint in signers:
        signed = sign_estate_catalog(
            signed, seed=seed, signer_id=signer_id, fingerprint=fingerprint
        )
    canonical = canonicalize(signed)
    complete_signing = len(signers) >= threshold
    if complete_signing:
        # Self-verify BEFORE writing, the discipline §4.4 requires of publish and
        # ARCHITECTURE-0.6.0.md:314 requires of bundle export. A catalog this build's
        # own verifier rejects never reaches the disk. Skipped only for a deliberately
        # under-signed artifact, which by construction cannot meet the threshold yet.
        verify_estate_catalog(
            signed,
            genesis_document=genesis_document,
            trust_log_checkpoint_bytes=checkpoint_bytes,
            expected_estate=_load_json_document(
                args.expected_estate, "--expected-estate", "expected_estate_file"
            ),
            authority=authority,
            file_bytes=canonical,
            expect_digest=digest,
        )
    _write_canonical_atomic(args.out, canonical)
    written = canonical
    verdict = "UNSIGNED_THRESHOLD_PENDING"
    signatures_verified = len(signers)
    if complete_signing:
        # Re-read the bytes that actually LANDED and verify those, not the in-memory
        # copy. The atomic write above already read them back byte-for-byte, so this is
        # the semantic re-verification rather than an I/O check.
        written = _read_catalog_bytes(args.out, "catalog")
        report = verify_estate_catalog(
            json.loads(written.decode("utf-8")),
            genesis_document=genesis_document,
            trust_log_checkpoint_bytes=checkpoint_bytes,
            expected_estate=_load_json_document(
                args.expected_estate, "--expected-estate", "expected_estate_file"
            ),
            authority=authority,
            file_bytes=written,
            expect_digest=digest,
        )
        verdict = report.verdict
        signatures_verified = report.signatures_verified

    plan["dry_run"] = False
    plan["written"] = args.out
    plan["canonical_len"] = len(written)
    plan["signatures_verified"] = signatures_verified
    plan["threshold_met"] = complete_signing
    plan["verdict"] = verdict
    if json_mode:
        _dump_json(plan)
    else:
        print("trust catalog: signed estate cutover catalog written")
        _print_catalog_plan(plan)
        print(f"  written:                 {args.out} ({len(written)} canonical bytes)")
        print(f"  self-verify:             {verdict} "
              f"({signatures_verified}/{threshold})")
        if not complete_signing:
            print("  THRESHOLD NOT YET MET: this catalog does NOT verify. Courier it to")
            print("  each remaining root and run `regista trust sign-catalog` there.")
        if catalog_status is not None:
            print("  *** CEREMONY FAILURE: catalog_status = partial. This catalog does")
            print("  *** NOT cover the expected estate and must not be treated as a")
            print(f"  *** successful cutover. Missing {len(missing)} project(s).")
        print("  PUBLISH IS A SEPARATE OPERATOR STEP: commit these exact bytes to the")
        print(f"  §4.2 publication clone at {publication_path}, then re-fetch through an")
        print("  independent checkout and run `regista trust verify-catalog`.")


def _print_catalog_plan(plan: dict[str, Any]) -> None:
    print(f"  catalog_kind:            {plan['catalog_kind']}")
    print(f"  catalog_status:          {plan['catalog_status']}")
    print(f"  trust_domain_id:         {plan['trust_domain_id']}")
    governance = plan["root_governance"]
    print(
        f"  root_governance:         {governance['mode']} "
        f"({governance['threshold']} of {governance['signer_count']})"
    )
    print(f"  root signer_ids:         {', '.join(plan['root_signer_ids'])}")
    print(f"  trust checkpoint:        seq {plan['trust_log_checkpoint_seq']} "
          f"{plan['trust_log_checkpoint_digest']}")
    print(f"  created_at:              {plan['created_at']}")
    print(f"  prev_commit:             {plan['prev_commit']}")
    print(f"  epoch facts:             {plan['epoch_facts_source']}")
    print(f"  projects:                {plan['project_count']} of "
          f"{plan['expected_project_count']} expected")
    for entry in plan["projects"]:
        source = plan["legacy_measurement_sources"][entry["project_name_hint"]]
        print(f"    - {entry['project_name_hint']}")
        print(f"        project_instance_id:      {entry['project_instance_id']}")
        print(f"        cutover_event_hash:       {entry['cutover_event_hash']}")
        print(f"        legacy_head_event_hash:   {entry['legacy_head_event_hash']} ({source})")
        print(f"        legacy_event_count:       {entry['legacy_event_count']}")
        print(f"        new_epoch_head:           {entry['new_epoch_head_event_hash']}")
    for missing in plan["missing_project_instance_ids"]:
        print(f"    ! MISSING: {missing}")
    print(f"  estate_catalog_digest:   {plan['estate_catalog_digest']}")


def cmd_trust_sign_catalog(args: argparse.Namespace) -> None:
    """Append one or more root signatures to an existing catalog. Offline, no database.

    This is the airgapped leg of a k-of-n ceremony (WI-330 review F5): `trust catalog`
    produces the document on the connected host with whatever root seeds are present
    there, and each remaining root runs this on its own machine. The document's signed
    core is never rebuilt — it is parsed, its canonical bytes are re-derived and
    compared, and only the ``root_signatures`` array grows. Nothing here can change what
    the catalog claims.

    Every signature already on the document is verified against the resolved root
    authority BEFORE anything is appended, and the whole array is verified again
    afterwards — so ``threshold_met`` counts verified signatures, not array entries
    (WI-330 review FR2-2).

    Like ``trust sign-genesis`` it never writes to the publication repo. It contacts a
    database only if ``--trust-log-project`` is given, which is how a rotated root set
    is proven rather than asserted.
    """
    from regista._estate_catalog import (
        estate_catalog_canonical_core,
        estate_catalog_digest,
        parse_estate_catalog,
        sign_estate_catalog,
        verify_catalog_root_signatures,
        verify_published_checkpoint,
    )
    from regista._jcs import canonicalize
    from regista._trust_domain import parse_trust_genesis, verify_trust_genesis

    json_mode = getattr(args, "json", False)
    _precheck_out_path(args.out, force=args.force, dry_run=False)

    genesis_document = _load_genesis_document(args.genesis)
    if genesis_document is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no trust-genesis document: pass --genesis PATH or set "
            "REGISTA_TRUST_GENESIS_PATH",
            {"reason": "genesis_document_absent"},
        )
    verify_trust_genesis(genesis_document)
    doc = parse_trust_genesis(genesis_document)

    authority = _resolve_root_authority(args, genesis_document)
    checkpoint_bytes = _read_catalog_bytes(args.trust_checkpoint, "trust-checkpoint")
    checkpoint = verify_published_checkpoint(
        checkpoint_bytes,
        genesis_document=genesis_document,
        authority=authority,
    )

    incoming_bytes = _read_catalog_bytes(args.file, "catalog")
    try:
        incoming = json.loads(incoming_bytes.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID,
            f"{args.file!r} is not valid JSON: {exc}",
            {"reason": "catalog_file_invalid_json", "path": args.file},
        ) from exc
    parsed = parse_estate_catalog(incoming, for_signing=True)
    if incoming_bytes != canonicalize(dict(incoming)):
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID,
            "the catalog being signed is not exact canonical JCS bytes; signing "
            "non-canonical bytes would produce an artifact that fails verification",
            {"reason": "not_canonical_publication_bytes", "path": args.file},
        )
    if parsed.trust_domain_id != doc.trust_domain_id:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_UNVERIFIED,
            f"the catalog is for trust domain {parsed.trust_domain_id!r} but the pinned "
            f"genesis is {doc.trust_domain_id!r}",
            {"reason": "trust_domain_mismatch"},
        )
    if parsed.root_governance != checkpoint.governance:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_UNVERIFIED,
            "the catalog's root_governance disagrees with the verified checkpoint's; "
            "refusing to add a signature to a document that already contradicts the "
            "trust state it will be verified against",
            {"reason": "root_governance_contradicts_checkpoint"},
        )
    if parsed.trust_log_checkpoint_digest != checkpoint.document_digest:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_UNVERIFIED,
            "the catalog binds a different trust-log checkpoint than the one supplied",
            {"reason": "trust_log_checkpoint_digest_mismatch"},
        )

    # FR2-2: every EXISTING signature must verify before this command touches the
    # document. A structurally-valid-but-cryptographically-invalid entry used to sit
    # there while a freshly appended good one pushed the count to threshold and the
    # command reported `threshold_met: true` — a claim an independent `verify-catalog`
    # then refused with `root_signature_invalid`. A count of unverified entries is not
    # a count of signatures.
    verify_catalog_root_signatures(incoming, parsed, authority)

    core_before = estate_catalog_canonical_core(incoming)
    signers = _catalog_signers(list(args.key), authority=authority)
    signed: dict[str, Any] = dict(incoming)
    for seed, signer_id, fingerprint in signers:
        signed = sign_estate_catalog(
            signed, seed=seed, signer_id=signer_id, fingerprint=fingerprint
        )
    # The claim must not have moved. Signing may only ever grow root_signatures.
    if estate_catalog_canonical_core(signed) != core_before:
        raise RegistaError(  # pragma: no cover - defensive
            ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID,
            "signing changed the catalog's signed core; refusing to write",
            {"reason": "signed_core_mutated"},
        )
    # And re-verify the WHOLE array afterwards, so `signatures_verified` below counts
    # only entries this command actually checked — never `len(root_signatures)`.
    verified = verify_catalog_root_signatures(
        signed, parse_estate_catalog(signed, for_signing=True), authority
    )
    canonical = canonicalize(signed)
    _write_canonical_atomic(args.out, canonical)

    threshold = authority.threshold
    result = {
        "ok": True,
        "action": "trust-sign-catalog",
        "written": args.out,
        "estate_catalog_digest": estate_catalog_digest(signed),
        "signatures_added": len(signers),
        "signatures_verified": len(verified),
        "signatures_total": len(signed["root_signatures"]),
        "threshold": threshold,
        "threshold_met": len(verified) >= threshold,
        "root_authority": authority.to_dict(),
        "root_fingerprints_added": [fingerprint for _, _, fingerprint in signers],
    }
    total = len(verified)
    if json_mode:
        _dump_json(result)
        return
    print("trust sign-catalog: root signature(s) appended")
    print(f"  in:                      {args.file}")
    print(f"  out:                     {args.out}")
    print(f"  estate_catalog_digest:   {result['estate_catalog_digest']}")
    print(f"  root authority:          {authority.source}")
    print(f"  signatures VERIFIED:     {total} of {threshold} required")
    if total >= threshold:
        print("  threshold MET: run `regista trust verify-catalog` before publishing.")
    else:
        print(f"  threshold NOT met: {threshold - total} more root signature(s) needed.")


def cmd_trust_verify_catalog(args: argparse.Namespace) -> None:
    """Verify a published estate cutover catalog; nonzero exit on anything but VALID.

    Offline and read-only: it reads the named files and nothing else. This is the
    runbook §5.4 step 5 check — run it against an INDEPENDENT checkout of the
    publication repository, with the pinned genesis document, the published trust-log
    checkpoint, the expected-estate manifest, and ideally the ``--expect-digest`` value
    obtained by direct exchange.

    There is no degraded mode. The checkpoint and the expected-estate manifest are
    REQUIRED, because "verify its signatures, catalog fields, and referenced heads"
    cannot be done without them: the checkpoint is what authorises the signing keys and
    fixes the threshold, and the manifest is the only thing against which "complete"
    can be falsified. Exit 3 means the catalog authenticated but declares itself
    ``catalog_status: partial`` — a ceremony failure, not a success.

    What it does NOT prove, and prints: the publication channel detects *substitution*,
    not initial dishonesty (§4.1, OPERATOR-FORGERY R3). A fresh clone cannot establish
    that the first publication was honest. Detection requires a prior observation —
    which is exactly what ``--expect-digest`` supplies.
    """
    from regista._estate_catalog import verify_estate_catalog

    json_mode = getattr(args, "json", False)

    genesis_document = _load_genesis_document(args.genesis)
    if genesis_document is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no trust-genesis document: pass --genesis PATH or set "
            "REGISTA_TRUST_GENESIS_PATH. The genesis supplies the initial root public "
            "keys; without it nothing about the catalog's authority can be checked and "
            "the verdict would be vacuous.",
            {"reason": "genesis_document_absent"},
        )

    file_bytes = _read_catalog_bytes(args.file, "catalog")
    try:
        document = json.loads(file_bytes.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID,
            f"{args.file!r} is not valid JSON: {exc}",
            {"reason": "catalog_file_invalid_json", "path": args.file},
        ) from exc

    checkpoint_bytes = _read_catalog_bytes(args.trust_checkpoint, "trust-checkpoint")
    expected_estate = _load_json_document(
        args.expected_estate, "--expected-estate", "expected_estate_file"
    )
    report = verify_estate_catalog(
        document,
        genesis_document=genesis_document,
        trust_log_checkpoint_bytes=checkpoint_bytes,
        expected_estate=expected_estate,
        authority=_resolve_root_authority(args, genesis_document),
        file_bytes=file_bytes,
        expect_digest=args.expect_digest,
    )
    if json_mode:
        _dump_json(report.to_dict())
    else:
        print(f"catalog_kind: {report.catalog_kind}")
        print(f"catalog_status: {report.catalog_status}")
        print(f"trust_domain_id: {report.trust_domain_id}")
        print(f"trust_domain_core_digest: {report.trust_domain_core_digest}")
        print(f"estate_catalog_digest: {report.estate_catalog_digest}")
        print(f"digest_pin: {report.digest_pin_status}")
        print(
            f"root_governance: {report.root_governance.mode} "
            f"({report.root_governance.threshold} of "
            f"{report.root_governance.signer_count})"
        )
        print(f"signatures_verified: {report.signatures_verified}")
        print(f"extra_signatures: {report.extra_signatures}")
        print(f"verified_fingerprints: {', '.join(report.verified_fingerprints)}")
        print(f"trust_log_checkpoint_digest: {report.trust_log_checkpoint_digest}")
        print(
            "trust_log_checkpoint: VERIFIED "
            f"(seq {report.checkpoint.checkpoint_seq}, "
            f"{report.checkpoint.signatures_verified} root signature(s))"
        )
        print(f"root_authority: {report.root_authority.source}")
        print(
            "active_root_fingerprints: "
            + ", ".join(report.root_authority.signer_fingerprints)
        )
        print(f"completeness: {report.completeness}")
        print(f"projects: {report.project_count}")
        for hint in report.project_name_hints:
            print(f"  - {hint}")
        for missing in report.missing_project_instance_ids:
            print(f"  ! MISSING: {missing}")
        print(f"verdict: {report.verdict}")
        if report.digest_pin_status != "matched":
            print(
                "NOTE: no --expect-digest was supplied. This checkout is internally "
                "coherent, which is NOT evidence that the first publication was honest "
                "(§4.1, OPERATOR-FORGERY R3). Substitution is detectable only against a "
                "prior observation."
            )
    if report.verdict != "VALID":
        # A partial catalog authenticated fine and is still a ceremony FAILURE
        # (RECONCILIATION.md:682-684). Exit 3 so a pipeline cannot read "no exception"
        # as success.
        print(
            "CEREMONY FAILURE: this catalog declares itself partial. It does not "
            "record a completed cutover.",
            file=sys.stderr,
        )
        sys.exit(3)


def _read_catalog_bytes(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise RegistaError(
            ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID,
            f"cannot read the {what} file {path!r}: {exc}",
            {"reason": f"{what.replace('-', '_')}_file_unreadable", "path": path},
        ) from exc


# --- WI-325: `regista genesis init` — the per-project v6 epoch opener -------------
#
# The per-project analog of `trust init-log`, and the last missing link of the
# EPOCH-RESET ceremony. Everything downstream of a project's genesis was already
# CLI-reachable; the opener itself was Python-API-only (`Regista.initialize_epoch`),
# and the only thing that ever built a `project_initialized` envelope lived in
# tests/_v6_fixtures.py.
#
# Two things make this more than a wrapper:
#
#  1. It assembles the envelope from LIVE trust-log facts (`_genesis_open`), and
#     verifies every one of them against the verified chain walk before signing. The
#     writer (`_genesis.append_v6_genesis`) checks that the acceptance is internally
#     consistent and that the signature verifies; nothing there checks that the
#     enrolled key, the enrolment event hash or the checkpoint head are REAL. That
#     check exists only here, because only here are the inputs still inputs.
#
#  2. It refuses to assert `gate_passed` without the EPOCH-RESET §5 verdict as
#     evidence, bound to this store fingerprint and this project.
#
# Refusal semantics mirror `trust init-log`: verify before touch, a named refusal for
# an already-opened epoch, an ACCURATE --dry-run that runs every check and writes
# nothing, and no --force. Re-opening an epoch would fork a project's identity, which
# is never a safe operation.


def _probe_project_store_state(dsn: str, project: str) -> dict[str, Any]:
    """Probe the TARGET project store before anything is written.

    Fails CLOSED with a named error rather than a raw psycopg traceback when the DSN
    is unreachable, the schema is absent, or the namespace holds something that is not
    a migrated regista project. Deliberately separate from
    :func:`_probe_trust_log_state`: that one asks "is this a trust log", this one asks
    "is this an empty, migrated, un-opened project".
    """
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.sql import SQL, Identifier

    from regista._connection import validate_project_name

    schema = validate_project_name(project)
    try:
        with psycopg.connect(
            dsn, connect_timeout=5, row_factory=dict_row, autocommit=True
        ) as conn:
            schema_row = conn.execute(
                "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
                [schema],
            ).fetchone()
            if schema_row is None:
                raise RegistaError(
                    ErrorCode.MIGRATION_REQUIRED,
                    f"schema {schema!r} does not exist. `genesis init` opens an epoch in "
                    "an ALREADY-PROVISIONED clean store; it does not create one. Run "
                    f"`regista provision --project {schema}` first.",
                    {"reason": "project_schema_absent", "project": schema},
                )
            conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
            try:
                events = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
                identity = conn.execute(
                    "SELECT COUNT(*) AS n FROM project_identity WHERE id = TRUE"
                ).fetchone()
                head = conn.execute(
                    "SELECT head_hash FROM event_chain_head WHERE id = TRUE"
                ).fetchone()
            except psycopg.errors.UndefinedTable as exc:
                raise RegistaError(
                    ErrorCode.MIGRATION_REQUIRED,
                    f"schema {schema!r} exists but lacks the clean-epoch baseline "
                    "(events / project_identity / event_chain_head). Either the "
                    "namespace belongs to something other than a regista project, or "
                    "migrations have not been applied. Recreate it with "
                    f"`regista provision --project {schema}` rather than importing "
                    "legacy history into a v6 epoch.",
                    {"reason": "project_schema_not_migrated", "project": schema},
                ) from exc
            archived = 0
            arch_row = conn.execute(
                "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE "
                "table_schema = %s AND table_name = 'events_archive') AS present",
                [schema],
            ).fetchone()
            if arch_row is not None and arch_row["present"]:
                arch_count = conn.execute(
                    "SELECT COUNT(*) AS n FROM events_archive"
                ).fetchone()
                archived = 0 if arch_count is None else int(arch_count["n"])
            return {
                "project": schema,
                "schema_exists": True,
                "live_event_count": 0 if events is None else int(events["n"]),
                "archived_event_count": archived,
                "identity_present": identity is not None and int(identity["n"]) > 0,
                "head_present": head is not None and head["head_hash"] is not None,
            }
    except RegistaError:
        raise
    except (psycopg.OperationalError, psycopg.Error) as exc:
        raise RegistaError(
            ErrorCode.TRUST_LOG_STORE_UNAVAILABLE,
            f"could not reach the target store to probe schema {schema!r}: {exc}. "
            "Check --dsn / REGISTA_DSN and that the database is reachable.",
            {"reason": "store_unreachable", "project": schema},
        ) from exc


def _genesis_require_trust_log(dsn: str, trust_project: str) -> None:
    """Refuse namedly when ``--trust-project`` does not name an initialised trust log."""
    _schema_exists, initialized = _probe_trust_log_state(dsn, trust_project)
    if not initialized:
        raise RegistaError(
            ErrorCode.TRUST_LOG_STORE_UNAVAILABLE,
            f"schema {trust_project!r} carries no trust_domain_established genesis, so "
            "there is no trust log to verify this project's genesis reference against. "
            "Check --trust-project (it defaults to the genesis document's signed "
            "project_name_hint), and run `regista trust init-log` if the estate's trust "
            "log has not been initialised.",
            {"reason": "trust_log_not_initialized", "project": trust_project},
        )


def _genesis_refusal_reason(state: Mapping[str, Any]) -> str | None:
    """The would-refuse reason a real run would raise, or ``None``.

    Computed from the probe so ``--dry-run`` reports the SAME outcome the real run
    would reach instead of an optimistic ``would_write: true`` — the accuracy failure
    the WI-319 review named (deepseek N4). The authoritative guard is still
    ``_genesis.first_write_admission``, under the global-chain sentinel lock.
    """
    if state["identity_present"]:
        return "project_identity_already_established"
    if state["live_event_count"]:
        return "live_events_already_exist"
    if state["archived_event_count"]:
        return "archived_events_already_exist"
    if state["head_present"]:
        return "chain_head_already_populated"
    return None


def _genesis_signing_key(key_path: str | None, enrolled: Any) -> Any:
    """Resolve the local keyset entry that will sign, and prove it IS the enrolled key.

    The writer resolves the key again (``_genesis._genesis_key``) and re-checks the
    acceptance against it, so this is a preflight — but it is the preflight that turns
    the live keyset/enrolment mismatch into an actionable message instead of an
    ACTOR_SIGNER_MISMATCH from inside the writer. The specific failure worth naming:
    a keyset entry that holds the byte-identical enrolled public key under a stale
    ``key_id``/``principal_id`` label, which is what `keys adopt-enrollment` fixes.
    """
    from regista._keys import KeySet

    if not key_path:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no signing keyset configured: pass --hmac-key-path or set REGISTA_KEY_PATH. "
            "A v6 genesis is signed by the enrolled host key, which must be loadable "
            "locally.",
            {"reason": "key_path_absent"},
        )
    key_set = KeySet(key_path)
    try:
        entry = key_set.resolve_signing_key(enrolled.principal_id, key_id=enrolled.key_id)
    except RegistaError as exc:
        holder = next(
            (
                row
                for row in key_set.describe_keys()
                if row.get("fingerprint") == enrolled.fingerprint
            ),
            None,
        )
        if holder is not None:
            raise RegistaError(
                ErrorCode.ACTOR_SIGNER_MISMATCH,
                f"the local keyset has no entry {enrolled.principal_id}/"
                f"{enrolled.key_id}, but entry "
                f"{holder.get('principal_id')!r}/{holder.get('key_id')!r} holds the "
                "byte-identical enrolled public key under a different label. Relabel it "
                f"with `regista keys adopt-enrollment --principal "
                f"{enrolled.principal_id}` — no key material moves.",
                {
                    "reason": "enrolled_key_held_under_stale_label",
                    "enrolled_principal_id": enrolled.principal_id,
                    "enrolled_key_id": enrolled.key_id,
                    "keyset_principal_id": holder.get("principal_id"),
                    "keyset_key_id": holder.get("key_id"),
                },
            ) from exc
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"the local keyset has no usable entry for {enrolled.principal_id}/"
            f"{enrolled.key_id}, and no entry holds that key's material at all. The "
            "enrolled private key must be in this host's custody to open an epoch as "
            "this principal.",
            {
                "reason": "enrolled_key_absent_from_keyset",
                "enrolled_principal_id": enrolled.principal_id,
                "enrolled_key_id": enrolled.key_id,
            },
        ) from exc
    if entry.scheme != "ed25519":
        raise RegistaError(
            ErrorCode.GENESIS_INVALID,
            f"keyset entry {entry.key_id!r} has scheme {entry.scheme!r}; a v6 genesis "
            "requires Ed25519",
            {"reason": "signing_key_not_ed25519", "scheme": entry.scheme},
        )
    if entry.public_key is None or entry.public_key != enrolled.public_key:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"keyset entry {enrolled.principal_id}/{enrolled.key_id} does not hold the "
            "public key the trust log enrolled under that identity. Refusing to sign a "
            "genesis whose acceptance would name key material this host does not have.",
            {
                "reason": "keyset_public_key_not_enrolled_key",
                "principal_id": enrolled.principal_id,
                "key_id": enrolled.key_id,
            },
        )
    # The entry's public_key field is a DECLARATION. Derive the public key from the
    # effective secret so the host is shown to hold the private half before anything is
    # signed. The writer proves the same thing the hard way — it signs and then verifies
    # under the bound public key (`_genesis.py:690-709`) — so this is a preflight for a
    # clear message, not the only guard.
    derived = _ed25519_public_from_secret(entry.secret)
    if derived != enrolled.public_key:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"keyset entry {enrolled.principal_id}/{enrolled.key_id} declares the "
            "enrolled public key, but its private material derives a different one (or "
            "is not a 32-byte Ed25519 seed). This host cannot sign as the enrolled "
            "identity; refusing before any signature is attempted.",
            {
                "reason": "keyset_secret_does_not_derive_enrolled_public_key",
                "principal_id": enrolled.principal_id,
                "key_id": enrolled.key_id,
            },
        )
    return entry


def cmd_genesis_init(args: argparse.Namespace) -> None:
    """Open a project's clean v6 epoch: one signed ``project_initialized`` event.

    The ordered ceremony, every step of which happens BEFORE any write:

      1. resolve config; refuse without a DSN and a project
      2. load and fully verify the pinned trust-genesis document
      3. resolve the process-level producer identity (refuses if unset — never a
         default, which would sign an invented harness name)
      4. validate the EPOCH-RESET §5 gate report and bind it to this store + project
      5. probe the target store: migrated, empty, epoch not yet opened
      6. walk the LIVE trust log under verification and resolve the enrolled key, its
         ``principal_key_enrolled`` hash, and the checkpoint triplet
      7. resolve the local signing key and prove it is that enrolled key
      8. measure the pre-genesis store state and build the envelope

    ``--dry-run`` performs 1-8 and stops. There is no ``--force``: a project's genesis
    establishes its permanent identity, so a second one would fork it.
    """
    from regista._connection import ConnectionManager
    from regista._genesis_open import (
        DEFAULT_SCOPE_ENTITY_KINDS,
        build_project_initialized_envelope,
        load_gate_evidence,
        measure_previous_epoch,
        resolve_trust_reference,
        validate_scope_entity_kinds,
    )
    from regista._trust_domain import parse_trust_genesis, verify_trust_genesis
    from regista._v6_writer import resolve_producer

    json_mode = getattr(args, "json", False)

    # (1) Config. The target project is the one being opened; it is NEVER the trust
    # log's schema, and confusing the two would write a project genesis into the
    # estate's trust log.
    dsn, project, key_path = _resolve_config(args)
    if not dsn:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "missing required config: --dsn or REGISTA_DSN",
            {"reason": "dsn_absent"},
        )
    if not project:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "missing required config: --project or REGISTA_PROJECT names the project "
            "whose epoch is being opened",
            {"reason": "project_absent"},
        )

    # (2) The pinned genesis document, fully verified. verify_trust_genesis raises on
    # anything short of VALID, so an unverified document never reaches a write path.
    genesis_document = _load_genesis_document(args.genesis)
    if genesis_document is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no trust-genesis document: pass --genesis PATH or set "
            "REGISTA_TRUST_GENESIS_PATH. A project epoch is opened INTO a trust domain; "
            "without the pinned document there is nothing to verify the trust "
            "reference against.",
            {"reason": "genesis_document_absent"},
        )
    verify_trust_genesis(genesis_document)
    doc = parse_trust_genesis(genesis_document)
    trust_project = args.trust_project or doc.trust_log.project_name_hint
    if trust_project == project:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"--project {project!r} is the trust log's own schema. `genesis init` opens "
            "an ORDINARY project's epoch; the trust log's genesis is "
            "`regista trust init-log` and its first event is trust_domain_established, "
            "not project_initialized.",
            {"reason": "target_project_is_trust_log", "project": project},
        )

    # A published checkpoint carries its OWN checkpoint_seq, so an explicit
    # --checkpoint-seq alongside it is a contradiction. Refusing beats silently
    # ignoring one of two conflicting operator instructions.
    if args.trust_checkpoint is not None and args.checkpoint_seq != 1:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--checkpoint-seq applies only to a DERIVED checkpoint; a published "
            "--trust-checkpoint document carries its own checkpoint_seq. Drop one of "
            "the two rather than have the tool choose which instruction to ignore.",
            {"reason": "checkpoint_seq_conflicts_with_published_checkpoint"},
        )
    publication_args = (args.trust_publication_repo, args.trust_publication_commit)
    if args.trust_checkpoint is not None and any(value is None for value in publication_args):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--trust-checkpoint requires both --trust-publication-repo and the "
            "out-of-band --trust-publication-commit pin",
            {"reason": "checkpoint_publication_pin_absent"},
        )
    if args.trust_checkpoint is None and any(value is not None for value in publication_args):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "--trust-publication-repo/--trust-publication-commit require "
            "--trust-checkpoint",
            {"reason": "checkpoint_publication_without_checkpoint"},
        )

    # (3) Producer identity. Load-bearing and process-level by design: unset is a
    # refusal naming the variables, never a default (V6-ENVELOPE.md §1.8).
    producer = resolve_producer().as_envelope_member()

    # Validate the operator's scope choice now, so a typo is a clear CLI refusal
    # rather than a GENESIS_INVALID out of the writer.
    entity_kinds = validate_scope_entity_kinds(
        args.scope_entity_kind or list(DEFAULT_SCOPE_ENTITY_KINDS)
    )

    # (4) The §5 first-write verdict, as evidence bound to THIS target.
    gate = load_gate_evidence(args.gate_report, dsn=dsn, project=project)

    # (5) The target store, probed before touch.
    state = _probe_project_store_state(dsn, project)
    refuse_reason = _genesis_refusal_reason(state)

    # The project's permanent identity. Minted here rather than inside the envelope
    # builder so a --dry-run reports the same value a real run would write.
    if args.project_instance_id is not None:
        try:
            project_instance_id = str(uuid.UUID(args.project_instance_id))
        except ValueError as exc:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"--project-instance-id {args.project_instance_id!r} is not a UUID",
                {"reason": "project_instance_id_not_uuid"},
            ) from exc
    else:
        project_instance_id = str(uuid.uuid4())

    # Refuse cleanly, with a named error, when the named schema is not an initialised
    # trust log — the common consequence of a wrong --trust-project. Without this the
    # failure surfaces from inside the chain walk as "empty_trust_log", which does not
    # tell the operator that they pointed at the wrong schema.
    _genesis_require_trust_log(dsn, trust_project)

    # (6) The live trust log, walked under verification. `occurred_at` is fixed here
    # and used for BOTH the enrolment validity-window check and the envelope's own
    # timestamp, so the instant the key is proven live at is exactly the instant the
    # event claims to have happened.
    occurred_at = datetime.now(UTC)
    trust_mgr = ConnectionManager(dsn, trust_project)
    try:
        trust_mgr.open()
        # NOT `SET TRANSACTION READ ONLY`: the verified walk takes `SELECT ... FOR
        # SHARE` row locks on `lifecycle_challenges` (the possession-evidence check,
        # `_trust_log_writer._verify_possession_evidence`), and PostgreSQL forbids row
        # locking in a read-only transaction. The transaction issues no
        # data-modifying statement — every statement on this path is a SELECT.
        with trust_mgr.transaction() as conn:
            reference = resolve_trust_reference(
                conn,
                genesis_document,
                principal_id=args.principal,
                key_id=args.key_id,
                expected_trust_event_hash=args.trust_event_hash,
                expected_trust_domain_id=args.trust_domain_id,
                at=occurred_at,
                checkpoint_seq=args.checkpoint_seq,
                published_checkpoint_path=args.trust_checkpoint,
                publication_repo=args.trust_publication_repo,
                publication_commit=args.trust_publication_commit,
                allow_derived_checkpoint=bool(args.dry_run),
            )
    finally:
        trust_mgr.close()
    if reference.checkpoint.source == "derived" and refuse_reason is None:
        # Dry-run is allowed to show the local observation, but it must report the
        # refusal the identical real invocation would receive rather than claiming
        # readiness that disappears when --dry-run is removed.
        refuse_reason = "published_checkpoint_required"

    # (7) The local signing key must BE the enrolled key.
    _genesis_signing_key(key_path, reference.key)

    # (8) Measure the pre-genesis store and build the envelope.
    target_mgr = ConnectionManager(dsn, project)
    try:
        target_mgr.open()
        with target_mgr.transaction() as conn:
            conn.execute("SET TRANSACTION READ ONLY")
            previous_epoch = measure_previous_epoch(conn)
    finally:
        target_mgr.close()

    envelope = build_project_initialized_envelope(
        project_instance_id=project_instance_id,
        reference=reference,
        producer=producer,
        previous_epoch=previous_epoch,
        gate=gate,
        occurred_at=occurred_at,
        scope_entity_kinds=entity_kinds,
        may_sign_bundles=args.may_sign_bundles,
    )

    plan: dict[str, Any] = {
        "action": "genesis-init",
        "project": project,
        "project_instance_id": project_instance_id,
        "transition": "project_initialized",
        "event_id": envelope["event_id"],
        "occurred_at": envelope["occurred_at"],
        "trust_log_project": trust_project,
        "trust_reference": reference.to_dict(),
        "gate": gate.to_dict(),
        "producer": producer,
        "scopes": envelope["payload"]["bootstrap_key_acceptance"]["scopes"],
        "previous_epoch": previous_epoch.to_dict(),
        "store": state,
    }

    if args.dry_run:
        plan["dry_run"] = True
        plan["would_write"] = refuse_reason is None
        if refuse_reason is not None:
            plan["would_refuse_reason"] = refuse_reason
        # The derived observation document the checkpoint digest covers, so a dry run
        # can be archived alongside the decision it informed.
        plan["checkpoint_document"] = dict(reference.checkpoint.document)
        if json_mode:
            _dump_json(plan)
        else:
            _print_genesis_plan(plan, reference, refuse_reason)
        return

    if refuse_reason is not None:
        raise RegistaError(
            ErrorCode.GENESIS_ALREADY_WRITTEN,
            f"project {project!r} has already opened an epoch or is not empty "
            f"({refuse_reason}); refusing to write a second genesis. A project's "
            "genesis establishes its permanent identity, so there is no --force.",
            {"reason": refuse_reason, **state},
        )

    handle = Regista(dsn, project, key_path)
    try:
        # gate_passed is True only because load_gate_evidence proved the §5 verdict
        # exists, passes, and is bound to this store and project. The writer re-runs
        # first_write_admission under the global-chain sentinel lock, so the
        # empty-store decision is made with the lock held, not from the probe above.
        write = handle.initialize_epoch(envelope, gate_passed=True)
        # Re-derive and verify the signed record without writing (EPOCH-RESET §5.1's
        # read side). A genesis that cannot be read back is not an opened epoch.
        recovered = handle.read_genesis()
    finally:
        handle.close()

    if recovered is None or recovered.event_hash != write.event_hash:
        raise RegistaError(
            ErrorCode.GENESIS_RECOVERY_FAILED,
            "the genesis was written but did not read back as the same signed event; "
            "the epoch is in an unverified state and must be investigated before use",
            {"reason": "post_write_recovery_mismatch", "project": project},
        )

    result = {
        "ok": True,
        "action": "genesis-init",
        "project": project,
        "transition": "project_initialized",
        **write.to_dict(),
        "trust_log_project": trust_project,
        "checkpoint": reference.checkpoint.to_dict(),
        "trust_event_hash": reference.key.trust_event_hash,
        "gate": gate.to_dict(),
        "verified_on_read": True,
    }
    if json_mode:
        _dump_json(result)
    else:
        print("genesis init: project_initialized written; epoch OPEN")
        print(f"  project (schema):        {project}")
        print(f"  project_instance_id:     {write.project_instance_id}")
        print(f"  trust_domain_id:         {write.trust_domain_id}")
        print(f"  event_id:                {write.event_id}")
        print(f"  event_hash:              sha256:{write.event_hash.hex()}")
        print(f"  signing principal:       {write.principal_id}")
        print(f"  signing key_id:          {write.key_id}")
        print(f"  key fingerprint:         {write.key_fingerprint}")
        print(f"  trust_event_hash:        {reference.key.trust_event_hash}")
        print(
            f"  checkpoint:              seq {reference.checkpoint.checkpoint_seq} "
            f"({reference.checkpoint.source})"
        )
        print(f"  gate report:             {gate.path}")
        print("  read back and verified:  yes")


def _print_genesis_plan(
    plan: Mapping[str, Any], reference: Any, refuse_reason: str | None
) -> None:
    print("genesis init: dry-run (nothing written)")
    print(f"  project (schema):        {plan['project']}")
    print(f"  project_instance_id:     {plan['project_instance_id']}")
    print(f"  trust_domain_id:         {reference.trust_domain_id}")
    print("  event to write:          project_initialized")
    print(f"  event_id:                {plan['event_id']}")
    print(f"  occurred_at:             {plan['occurred_at']}")
    print(f"  trust log (schema):      {plan['trust_log_project']}")
    print(f"  signing principal:       {reference.key.principal_id}")
    print(f"  signing key_id:          {reference.key.key_id}")
    print(f"  key fingerprint:         {reference.key.fingerprint}")
    print(f"  trust_event_hash:        {reference.key.trust_event_hash}")
    print(f"  enrolment window:        {reference.key.to_dict()['not_before']} .. "
          f"{reference.key.to_dict()['not_after'] or '(open)'}")
    print(f"  projection cross-check:  {reference.key.projection}")
    print(f"  checkpoint source:       {reference.checkpoint.source}")
    print(f"  checkpoint_seq:          {reference.checkpoint.checkpoint_seq}")
    print(f"  checkpoint head:         {reference.checkpoint.head_event_hash}")
    print(f"  checkpoint digest:       {reference.checkpoint.document_digest}")
    if reference.checkpoint.source == "derived":
        print("    NOTE: no published checkpoint document was supplied, so the digest")
        print("    covers a LOCAL, UNSIGNED observation of the trust log made by this")
        print("    process. Pass --trust-checkpoint PATH to reference a published one.")
    print(f"  gate report:             {plan['gate']['path']}")
    print(f"  gate findings passed:    {plan['gate']['findings']}")
    print(f"  producer:                {plan['producer']['harness']} "
          f"{plan['producer']['harness_version']}")
    print(f"  acceptance entity kinds: {', '.join(plan['scopes']['entity_kinds'])}")
    print(f"  may_sign_bundles:        {plan['scopes']['may_sign_bundles']}")
    print(f"  store live events:       {plan['store']['live_event_count']}")
    print(f"  store archived events:   {plan['store']['archived_event_count']}")
    print(f"  epoch already open:      {plan['store']['identity_present']}")
    print(f"  would write:             {plan['would_write']}")
    if refuse_reason is not None:
        print(f"  would refuse (reason):   {refuse_reason}")


# --- WI-325: `regista keys adopt-enrollment` --------------------------------------
#
# The keyset/enrolment label gap, in the concrete: `trust enroll` records a key_id of
# its own choosing in the trust log, but nothing writes back to the local keyset, and
# `provision-principal` no longer mints keys. So a host can hold the enrolled PRIVATE
# key under an older key_id/principal label and be unable to sign as the identity the
# trust log knows — while the two entries are byte-identical key material.
#
# This command closes that with the narrowest possible write: it finds the keyset entry
# whose PUBLIC KEY equals the enrolled one and rewrites exactly two fields, `key_id`
# and `principal_id`. It never generates, moves, re-encodes or reads out private
# material; it refuses on ambiguity; it backs the file up first; and it proves after
# writing that the effective signing bytes are unchanged.


def cmd_keys_adopt_enrollment(args: argparse.Namespace) -> None:
    """Relabel the local keyset entry that already holds the enrolled key.

    Fail-closed by construction: exactly one entry may match the enrolled public key,
    the target ``key_id`` may not already be taken by a different entry, the matched
    entry must be a usable Ed25519 actor key, and the post-write self-check must show
    the effective key bytes are byte-identical. There is no ``--force``: two entries
    holding the same key material is a custody question, not something to guess at.
    """
    import shutil
    import stat
    import tempfile

    from regista._config import resolve as resolve_config
    from regista._connection import ConnectionManager
    from regista._doctor import _resolve_key_file_path
    from regista._genesis_open import resolve_enrolled_key
    from regista._keys import KeySet
    from regista._trust_domain import parse_trust_genesis, verify_trust_genesis

    json_mode = getattr(args, "json", False)

    dsn, _project, cli_key_path = _resolve_config(args)
    if not dsn:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "missing required config: --dsn or REGISTA_DSN (the enrolled identity is "
            "read from the live trust log, never from a flag)",
            {"reason": "dsn_absent"},
        )
    key_path = cli_key_path or resolve_config().key_path
    if not key_path:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no keyset configured: pass --hmac-key-path or set REGISTA_KEY_PATH",
            {"reason": "key_path_absent"},
        )
    fs_path = _resolve_key_file_path(key_path)
    if fs_path is None:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"cannot resolve key path {key_path!r} to a filesystem path",
            {"reason": "key_path_unresolvable"},
        )

    genesis_document = _load_genesis_document(args.genesis)
    if genesis_document is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "no trust-genesis document: pass --genesis PATH or set "
            "REGISTA_TRUST_GENESIS_PATH",
            {"reason": "genesis_document_absent"},
        )
    verify_trust_genesis(genesis_document)
    doc = parse_trust_genesis(genesis_document)
    trust_project = args.trust_project or doc.trust_log.project_name_hint

    _genesis_require_trust_log(dsn, trust_project)
    mgr = ConnectionManager(dsn, trust_project)
    try:
        mgr.open()
        # Not read-only, for the same reason as `genesis init`: the verified walk takes
        # FOR SHARE row locks on lifecycle_challenges. No statement here modifies data.
        with mgr.transaction() as conn:
            enrolled = resolve_enrolled_key(
                conn,
                genesis_document,
                principal_id=args.principal,
                key_id=args.key_id,
            )
    finally:
        mgr.close()

    raw_text = Path(fs_path).read_text(encoding="utf-8")
    document = json.loads(raw_text)
    entries = document.get("keys")
    if not isinstance(entries, list):
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"keyset {fs_path!r} has no 'keys' array",
            {"reason": "keyset_malformed"},
        )

    # Match on the PUBLIC KEY BYTES, not on any label. That is the whole point: the
    # labels are what disagree.
    matches = [
        (index, entry)
        for index, entry in enumerate(entries)
        if isinstance(entry, dict)
        and isinstance(entry.get("public_key"), str)
        and _decode_keyset_public_key(entry["public_key"]) == enrolled.public_key
    ]
    if not matches:
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"no entry in {fs_path!r} holds the public key enrolled for "
            f"{enrolled.principal_id}/{enrolled.key_id} (fingerprint "
            f"{enrolled.fingerprint}). This command RELABELS an entry that already "
            "holds the enrolled material; it never creates key material. The enrolled "
            "private key must be brought into this host's custody first.",
            {
                "reason": "no_keyset_entry_holds_enrolled_key",
                "principal_id": enrolled.principal_id,
                "key_id": enrolled.key_id,
                "fingerprint": enrolled.fingerprint,
            },
        )
    if len(matches) > 1:
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"{len(matches)} entries in {fs_path!r} hold the same enrolled public key "
            f"({', '.join(str(e.get('key_id')) for _i, e in matches)}); refusing to "
            "guess which one is the enrolled identity. Remove the duplicates first — "
            "two entries for one key is a custody question, not a labelling one.",
            {
                "reason": "ambiguous_keyset_entries",
                "key_ids": [str(e.get("key_id")) for _i, e in matches],
            },
        )

    index, entry = matches[0]
    old_key_id = str(entry.get("key_id"))
    old_principal = entry.get("principal_id")
    already = old_key_id == enrolled.key_id and old_principal == enrolled.principal_id

    collision = next(
        (
            e
            for i, e in enumerate(entries)
            if i != index and isinstance(e, dict) and e.get("key_id") == enrolled.key_id
        ),
        None,
    )
    if collision is not None:
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"keyset {fs_path!r} already has a DIFFERENT entry with key_id "
            f"{enrolled.key_id!r} (principal {collision.get('principal_id')!r}). "
            "Adopting the enrolled label would collide with it; resolve that entry "
            "first.",
            {"reason": "target_key_id_already_present", "key_id": enrolled.key_id},
        )
    if entry.get("scheme") != "ed25519":
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"keyset entry {old_key_id!r} declares scheme {entry.get('scheme')!r}; the "
            "enrolled identity is Ed25519, so relabelling this entry would make the "
            "keyset self-contradictory",
            {"reason": "matched_entry_not_ed25519", "scheme": entry.get("scheme")},
        )
    if entry.get("role", "actor") != "actor" or entry.get("status", "active") != "active":
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"keyset entry {old_key_id!r} is role={entry.get('role', 'actor')!r} "
            f"status={entry.get('status', 'active')!r}; a v6 genesis needs an ACTIVE "
            "ACTOR key. Adopting the enrolled label onto an unusable entry would only "
            "move the failure later. Fix role/status deliberately, by hand.",
            {
                "reason": "matched_entry_not_active_actor",
                "role": entry.get("role", "actor"),
                "status": entry.get("status", "active"),
            },
        )

    # PREFLIGHT: the matched entry must actually hold the enrolled PRIVATE key. Matching
    # on the public_key field only proves the entry DECLARES that key; deriving the
    # public key from the effective secret proves the host can sign as it. Refusing here
    # means the file is never touched for an entry that could not have been used anyway.
    before_entry = KeySet(fs_path).get_key(old_key_id)
    before_public = _ed25519_public_from_secret(before_entry.secret)
    if before_public is None:
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"keyset entry {old_key_id!r} does not hold a usable 32-byte Ed25519 seed, "
            "so it cannot be the enrolled signing key however it is labelled. Nothing "
            "was changed.",
            {"reason": "matched_entry_secret_not_an_ed25519_seed", "key_id": old_key_id},
        )
    if before_public != enrolled.public_key:
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"keyset entry {old_key_id!r} declares the enrolled public key but its "
            "SECRET derives a different one — the entry's public_key field and its "
            "private material disagree. Relabelling it would produce a keyset that "
            "cannot sign as the identity it claims. Nothing was changed.",
            {
                "reason": "matched_entry_secret_does_not_match_declared_public_key",
                "key_id": old_key_id,
            },
        )

    changes: list[dict[str, Any]] = (
        []
        if already
        else [
            {"field": "key_id", "from": old_key_id, "to": enrolled.key_id},
            {"field": "principal_id", "from": old_principal, "to": enrolled.principal_id},
        ]
    )
    plan: dict[str, Any] = {
        "action": "keys-adopt-enrollment",
        "key_path": fs_path,
        "principal_id": enrolled.principal_id,
        "enrolled_key_id": enrolled.key_id,
        "fingerprint": enrolled.fingerprint,
        "trust_event_hash": enrolled.trust_event_hash,
        "matched_entry": {"key_id": old_key_id, "principal_id": old_principal},
        "already_adopted": already,
        "changes": changes,
    }

    if already or args.dry_run:
        plan["dry_run"] = bool(args.dry_run)
        plan["would_write"] = bool(not already)
        if json_mode:
            _dump_json(plan)
        else:
            header = (
                "keys adopt-enrollment: already adopted (nothing to do)"
                if already
                else "keys adopt-enrollment: dry-run (nothing written)"
            )
            print(header)
            print(f"  keyset:                  {fs_path}")
            print(f"  enrolled identity:       {enrolled.principal_id}/{enrolled.key_id}")
            print(f"  fingerprint:             {enrolled.fingerprint}")
            print(f"  matched entry:           {old_principal}/{old_key_id}")
            for change in changes:
                print(
                    f"  would set {change['field']}: {change['from']!r} -> "
                    f"{change['to']!r}"
                )
        return

    # Back up BEFORE the write, preserving the original's mode (the file holds key
    # material or a secret_ref; a 0644 backup of a 0600 keyset would be a real leak).
    mode = stat.S_IMODE(Path(fs_path).stat().st_mode)
    backup = f"{fs_path}.bak.{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    try:
        shutil.copy2(fs_path, backup)
        os.chmod(backup, mode)
    except OSError as exc:
        # No backup, no rewrite. A keyset edit without a recoverable original is not a
        # risk worth taking for a convenience relabel, and a raw OSError here would read
        # as though the rewrite had been attempted.
        raise RegistaError(
            ErrorCode.KEYSET_ADOPTION_REFUSED,
            f"could not back up {fs_path!r} to {backup!r} ({exc}); refusing to rewrite "
            "a keyset with no recoverable original. Nothing was changed.",
            {"reason": "backup_failed", "key_path": fs_path, "backup": backup},
        ) from exc

    # Rewrite ONLY the two label fields. Every other field — secret, secret_ref,
    # encoding, public_key, role, status — is carried through untouched, so no private
    # material is re-encoded or moved.
    entry["key_id"] = enrolled.key_id
    entry["principal_id"] = enrolled.principal_id

    directory = os.path.dirname(os.path.abspath(fs_path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".regista-keys-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=False)
            handle.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, fs_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:  # pragma: no cover - cleanup must not mask the real failure
            pass
        raise

    # POST-WRITE: prove custody did not change. The effective SECRET behind the NEW
    # label must still derive the enrolled public key. This is what distinguishes a
    # relabel from a key swap, and it is not hypothetical: `KeySet` resolves a per-key
    # env override named REGISTA_HMAC_KEY_<KEY_ID>, so renaming the key_id changes WHICH
    # variable supplies the secret — an entry whose real material arrived through an
    # override keyed to the old label silently falls back to its inline `secret` after
    # the rewrite. A relabel that swapped a project's signing key would be the worst
    # possible outcome of a convenience command.
    try:
        try:
            after_entry = KeySet(fs_path).get_key(enrolled.key_id)
        except Exception as exc:
            # A bare KEY_LOAD_ERROR would leave the operator holding an unloadable keyset
            # with no indication that the original survives.
            raise RegistaError(
                ErrorCode.KEYSET_ADOPTION_REFUSED,
                f"post-write self-check failed: the relabelled keyset no longer loads "
                f"({exc}).",
                {"reason": "post_write_keyset_unloadable", "backup": backup},
            ) from exc
        after_public = _ed25519_public_from_secret(after_entry.secret)
        if after_public != before_public or after_public != enrolled.public_key:
            raise RegistaError(
                ErrorCode.KEYSET_ADOPTION_REFUSED,
                f"post-write self-check failed: the private material behind "
                f"{enrolled.key_id!r} no longer derives the enrolled public key, so the "
                f"relabel changed which key this entry signs with rather than only its "
                "label. (A per-key REGISTA_HMAC_KEY_<KEY_ID> override tied to the old "
                "key_id is the usual cause.)",
                {
                    "reason": "post_write_secret_changed",
                    "backup": backup,
                    "key_id": enrolled.key_id,
                    "previous_key_id": old_key_id,
                },
            )
        if after_entry.public_key != enrolled.public_key:
            raise RegistaError(
                ErrorCode.KEYSET_ADOPTION_REFUSED,
                "post-write self-check failed: the adopted entry's public_key field is "
                "not the enrolled key.",
                {"reason": "post_write_public_key_not_enrolled", "backup": backup},
            )
    except RegistaError as exc:
        # The command promises a relabel, not a possibly-mutated keyset plus recovery
        # instructions. Restore through a same-directory temporary so the rollback is
        # atomic too, while retaining the backup as durable audit/recovery evidence.
        restore_tmp: str | None = None
        try:
            restore_fd, restore_tmp = tempfile.mkstemp(
                prefix=".regista-keys-restore-", dir=directory
            )
            os.close(restore_fd)
            shutil.copy2(backup, restore_tmp)
            os.chmod(restore_tmp, mode)
            os.replace(restore_tmp, fs_path)
        except OSError as restore_exc:
            if restore_tmp is not None:
                try:
                    os.unlink(restore_tmp)
                except OSError:  # pragma: no cover - cleanup must not mask the refusal
                    pass
            raise RegistaError(
                ErrorCode.KEYSET_ADOPTION_REFUSED,
                "post-write verification failed and the automatic rollback also failed; "
                f"the keyset may be partially relabelled. Restore {backup!r} before use.",
                {
                    "reason": "post_write_restore_failed",
                    "original_reason": (exc.detail or {}).get("reason"),
                    "backup": backup,
                    "key_path": fs_path,
                    "partial": True,
                },
            ) from restore_exc
        detail = {**(exc.detail or {}), "restored": True, "partial": False}
        raise RegistaError(
            exc.code,
            f"{exc.message} The original keyset was restored automatically; the "
            f"backup remains at {backup!r}.",
            detail,
        ) from exc

    result = {
        **plan,
        "ok": True,
        "backup": backup,
        "verified_private_key_unchanged": True,
    }
    if json_mode:
        _dump_json(result)
    else:
        print("keys adopt-enrollment: entry relabelled to the enrolled identity")
        print(f"  keyset:                  {fs_path}")
        print(f"  backup:                  {backup}")
        print(f"  key_id:                  {old_key_id} -> {enrolled.key_id}")
        print(f"  principal_id:            {old_principal} -> {enrolled.principal_id}")
        print(f"  fingerprint:             {enrolled.fingerprint}")
        print("  private key unchanged:   yes (re-derived from the effective secret)")
        print(f"  enrolled by event:       {enrolled.trust_event_hash}")


def _ed25519_public_from_secret(secret: bytes) -> bytes | None:
    """Derive the Ed25519 public key from a keyset entry's EFFECTIVE secret bytes.

    This is the only honest way to ask "does this host actually hold the private half of
    the enrolled key?". ``KeySet.describe_keys()``'s fingerprint cannot answer it: for an
    asymmetric entry ``KeyEntry.fingerprint()`` digests the entry's ``public_key`` FIELD
    (``_keys.py:72-74``), which is a declaration, not a derivation — so two entries with
    the same ``public_key`` and different secrets fingerprint identically. Deriving from
    the secret closes that gap.

    Returns ``None`` rather than raising when the bytes are not a usable 32-byte seed;
    the caller turns that into a named refusal. A 64-byte libsodium secret key is
    deliberately NOT accepted by truncation — silently reinterpreting key material is
    the effective-key trap WI-236 exists to prevent.
    """
    import nacl.signing

    if len(secret) != 32:
        return None
    try:
        return bytes(nacl.signing.SigningKey(secret).verify_key)
    except (ValueError, TypeError):
        return None


def _decode_keyset_public_key(value: str) -> bytes | None:
    """Best-effort base64 decode of a keyset ``public_key``; ``None`` when it is not.

    Returning ``None`` rather than raising keeps a single unparseable entry from
    blocking adoption for a keyset whose OTHER entries are fine — a malformed neighbour
    is not evidence about the entry being adopted. ``None`` never compares equal to the
    enrolled bytes, so an unparseable entry simply cannot match.
    """
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:  # binascii.Error is a ValueError subclass
        return None


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

    # WI-325: relabel the local keyset entry that already holds the enrolled key.
    # `trust enroll` chooses the trust log's key_id; nothing writes back to the keyset,
    # so a host can hold the enrolled PRIVATE key under a stale label and be unable to
    # sign as the identity the trust log knows. This rewrites exactly two label fields.
    keys_adopt = keys_sub.add_parser(
        "adopt-enrollment",
        help="Relabel the keyset entry holding the enrolled public key to its "
        "enrolled key_id/principal_id. Matches on public-key BYTES, never on a "
        "label; refuses on ambiguity; backs the file up first; never generates, "
        "moves or re-encodes private material",
    )
    keys_adopt.add_argument(
        "--principal",
        required=True,
        help="Canonical kind:subject principal id whose enrolment to adopt "
        "(e.g. agent:example-host)",
    )
    keys_adopt.add_argument(
        "--key-id",
        default=None,
        help="Adopt this specific enrolled key_id; required only when the principal "
        "has more than one active enrolled key",
    )
    keys_adopt.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned trust-genesis JSON (or REGISTA_TRUST_GENESIS_PATH)",
    )
    keys_adopt.add_argument(
        "--trust-project",
        default=None,
        help="Trust-log schema to read the enrolment from; defaults to the genesis "
        "document's signed project_name_hint (regista_trust)",
    )
    keys_adopt.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve the enrolment, match the entry and print the plan; write NOTHING",
    )
    keys_adopt.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )
    keys_adopt.set_defaults(func=cmd_keys_adopt_enrollment)

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
    # TRUST-DOMAIN.md §2.2 — the mandated lookup verb for the one-way backend-safe name.
    pr_resolve = pr_sub.add_parser(
        "resolve-backend-name",
        help="Reverse a §2.2 backend-safe secret name (rp-<32 hex>) to its principal_id",
    )
    pr_resolve.add_argument(
        "backend_name",
        metavar="BACKEND_NAME",
        help="The derived name as it appears in the secret backend, e.g. rp-ef29a698...",
    )
    pr_resolve.add_argument(
        "--principal-id",
        help="Confirm one candidate instead of searching the registry (needs no database)",
    )
    pr_resolve.add_argument("--json", action="store_true", help="JSON output")
    pr_resolve.set_defaults(func=cmd_principal_resolve_backend_name)
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

    # trust (0.6.0 P2.1 — offline trust-domain genesis helpers; no database)
    trust_parser = subs.add_parser("trust", help="Trust-domain genesis commands (offline)")
    trust_sub = trust_parser.add_subparsers(dest="subcommand")
    trust_sign = trust_sub.add_parser(
        "sign-genesis",
        help="Offline: sign a trust-genesis document and write a detached signature",
    )
    trust_sign.add_argument("--core", required=True, help="Path to the genesis document JSON")
    trust_sign.add_argument(
        "--key", required=True, help="Path to a 32-byte Ed25519 seed (64 hex chars or base64)"
    )
    trust_sign.add_argument("--out", required=True, help="Detached signature output path")
    trust_sign.add_argument(
        "--signed-at",
        help="Override the signed_at claim (microsecond UTC Z form); default: now",
    )
    trust_sign.add_argument(
        "--force",
        action="store_true",
        help="Silently replace an existing --out file (refused by default)",
    )
    trust_sign.set_defaults(func=cmd_trust_sign_genesis)
    trust_verify = trust_sub.add_parser(
        "verify-genesis",
        help="Verify a trust-genesis document; nonzero exit on invalid",
    )
    trust_verify.add_argument("file", help="Path to the genesis document JSON")
    trust_verify.add_argument("--json", action="store_true", help="JSON output")
    trust_verify.set_defaults(func=cmd_trust_verify_genesis)
    # §5.9 rule 4: the rebuild is a first-class command, so hand-fixing a row is
    # never the easier option. This one DOES touch the database, unlike its two
    # offline siblings above.
    trust_rebuild = trust_sub.add_parser(
        "rebuild-projection",
        help="Rebuild principal_keys from signed trust-log events (§5.9)",
    )
    # SUPPRESS, not a plain default: a subparser option with a None default
    # overwrites the global --project/--dsn the top-level parser already set, so the
    # command would silently lose its configuration. The contract names
    # `--project` here (§5.9 rule 4), so it is accepted and simply defers to the
    # global value when omitted.
    trust_rebuild.add_argument(
        "--project",
        default=argparse.SUPPRESS,
        help="Project (schema) to rebuild; defaults to the global --project",
    )
    trust_rebuild.add_argument(
        "--dry-run",
        action="store_true",
        help="Rebuild into a temp table and report the diff; write nothing. "
        "Exits non-zero if the live projection has diverged.",
    )
    trust_rebuild.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned trust-genesis JSON (A-prime; optional only for "
        "an empty trust log; otherwise REGISTA_TRUST_GENESIS_PATH may supply it)",
    )
    # Also SUPPRESS: `regista --json trust rebuild-projection` must stay JSON.
    # A store_true default of False here would silently override the global flag.
    trust_rebuild.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output",
    )
    trust_rebuild.set_defaults(func=cmd_trust_rebuild_projection)

    # WI-319: initialize the estate-wide trust log — write its genesis
    # trust_domain_established event from a published, VALID genesis document plus the
    # root Ed25519 seed. This DOES touch the database (creates the trust-log schema if
    # needed); it is the write that unblocks per-host provisioning.
    trust_init = trust_sub.add_parser(
        "init-log",
        help="Write the trust log's genesis event into a database (§5.2)",
    )
    trust_init.add_argument(
        "--genesis",
        default=None,
        help="Path to the published, VALID trust-genesis JSON (or "
        "REGISTA_TRUST_GENESIS_PATH)",
    )
    trust_init.add_argument(
        "--key",
        required=True,
        help="Path to the root's 32-byte Ed25519 seed (64 hex chars or base64); "
        "its fingerprint must be a genesis signer",
    )
    trust_init.add_argument(
        "--root-principal-id",
        default=None,
        help="Canonical kind:subject principal id recorded as the genesis event's "
        "actor (e.g. service:root-a). OPTIONAL: when omitted it defaults from the "
        "genesis's SIGNED initial_custody declared_holder (requires exactly one custody "
        "entry whose holder is a canonical principal id). When given it is VERIFY-ONLY "
        "(WI-320): it must EQUAL the declared_holder of the custody entry for the "
        "supplied --key's fingerprint, else the write is refused — it confirms the signed "
        "declaration, it cannot override it. NOTE: declared_holder is signed but "
        "operator-declared, so the actor is still not cryptographically bound to the "
        "root signature; that residual binding is tracked by WI-320.",
    )
    # SUPPRESS (see rebuild-projection): a subparser --project/--json with a None/False
    # default would clobber the global value the top-level parser already set.
    trust_init.add_argument(
        "--project",
        default=argparse.SUPPRESS,
        help="Trust-log project (schema); defaults to the global --project, else the "
        "genesis document's project_name_hint (regista_trust)",
    )
    trust_init.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify the document and root key and print the plan; write NOTHING",
    )
    trust_init.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output",
    )
    trust_init.set_defaults(func=cmd_trust_init_log)

    # WI-319 (2/3): enrol a principal's Ed25519 key INTO the initialised trust log.
    # The v6-native verifier/commit counterpart of the `signer` client commands. Two
    # phases: `--issue-challenge` prints a possession challenge; the default commits the
    # enrollee's proof as a registrar-authorised principal_key_enrolled event.
    trust_enroll = trust_sub.add_parser(
        "enroll",
        help="Enrol a principal key into the trust log (§5.5); registrar-authorised",
    )
    trust_enroll.add_argument(
        "--principal",
        required=True,
        help="Enrollee canonical kind:subject principal id (e.g. agent:host-01)",
    )
    trust_enroll.add_argument(
        "--public-key",
        required=True,
        help="Enrollee's base64-encoded 32-byte Ed25519 public key (from "
        "`regista signer generate`)",
    )
    trust_enroll.add_argument(
        "--issue-challenge",
        action="store_true",
        help="Phase 1: issue and persist a fresh possession challenge, print its JSON, "
        "and exit. Hand the JSON to the enrollee for `regista signer sign-possession`.",
    )
    trust_enroll.add_argument(
        "--ttl-minutes",
        type=int,
        default=None,
        help="Possession-challenge validity window in minutes (default 30); "
        "--issue-challenge only",
    )
    trust_enroll.add_argument(
        "--proof",
        default=None,
        help="Phase 2: the possession proof JSON from `signer sign-possession` "
        "(else --proof-file, else stdin)",
    )
    trust_enroll.add_argument(
        "--proof-file",
        default=None,
        help="Phase 2: path to the possession proof JSON",
    )
    trust_enroll.add_argument(
        "--key",
        default=None,
        help="Phase 2: path to the authorising registrar's 32-byte Ed25519 seed "
        "(64 hex chars or base64); must be the key of a live registrar delegation",
    )
    trust_enroll.add_argument(
        "--registrar-principal-id",
        default=None,
        help="Phase 2: canonical principal id of the delegated registrar authorising "
        "this enrolment (e.g. service:registrar-1)",
    )
    trust_enroll.add_argument(
        "--custody-backend",
        default=None,
        help="Declared custody backend recorded on the event "
        "(vault/azure/windows/file/operator; default operator)",
    )
    trust_enroll.add_argument(
        "--policy-ref",
        default=None,
        help="Declared custody policy reference recorded on the event",
    )
    trust_enroll.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned trust-genesis JSON (or REGISTA_TRUST_GENESIS_PATH)",
    )
    # SUPPRESS (see rebuild-projection/init-log): a subparser --project/--json with a
    # None/False default would clobber the global value the top-level parser already set.
    trust_enroll.add_argument(
        "--project",
        default=argparse.SUPPRESS,
        help="Trust-log project (schema); defaults to the global --project, else the "
        "genesis document's project_name_hint (regista_trust)",
    )
    trust_enroll.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify and print the plan; write NOTHING",
    )
    trust_enroll.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output",
    )
    trust_enroll.set_defaults(func=cmd_trust_enroll)

    # WI-321 (3/3): the missing middle link — ROOT delegates registrar power. Genesis
    # (init-log) is written and hosts want to enrol (enroll), but enrolment is
    # registrar-authorised: without a root-signed registrar_delegated event nothing can be
    # enrolled. This command writes that event. It DOES touch the database.
    trust_deleg = trust_sub.add_parser(
        "delegate-registrar",
        help="Delegate scoped, expiring registrar authority under root (§5.4)",
    )
    trust_deleg.add_argument(
        "--registrar-principal-id",
        required=True,
        help="Canonical kind:subject principal id being granted registrar authority "
        "(e.g. service:registrar-1)",
    )
    trust_deleg.add_argument(
        "--registrar-public-key",
        required=True,
        help="Base64-encoded 32-byte Ed25519 public key of the registrar's key",
    )
    trust_deleg.add_argument(
        "--registrar-key-id",
        required=True,
        help="key_id granted to the registrar (1-128 chars of [A-Za-z0-9._:-])",
    )
    trust_deleg.add_argument(
        "--key",
        required=True,
        help="Path to the ROOT authorising 32-byte Ed25519 seed (64 hex chars or "
        "base64); its fingerprint must be a current genesis signer",
    )
    trust_deleg.add_argument(
        "--root-principal-id",
        default=None,
        help="Canonical kind:subject principal id recorded as the delegation event's "
        "actor (e.g. service:root-a). OPTIONAL: defaults from the genesis's SIGNED "
        "initial_custody declared_holder (requires exactly one custody entry whose "
        "holder is canonical). When given it is VERIFY-ONLY (WI-320): it must EQUAL the "
        "declared_holder of the custody entry for the supplied --key's fingerprint, else "
        "the delegation is refused. NOTE: declared_holder is signed but operator-declared, "
        "so the actor is still not cryptographically bound to the root signature (WI-320).",
    )
    trust_deleg.add_argument(
        "--scope",
        action="append",
        default=None,
        help="A transition the registrar may authorise; repeatable and comma-joinable. "
        "Default: principal_key_enrolled,principal_key_rotated,principal_key_revoked. "
        "Must be within the registrar lifecycle-administration scope set (§5.4).",
    )
    trust_deleg.add_argument(
        "--not-before",
        default=None,
        help="Delegation validity start (microsecond UTC Z form); default: now - 1h. "
        "NOTE: idempotent re-runs require pinning BOTH --not-before and --not-after — "
        "the defaults anchor to call-time now() at microsecond resolution, so a "
        "byte-identical re-run WITHOUT pinned windows differs and is refused "
        "(registrar_already_delegated_live), which is fail-safe, not a no-op.",
    )
    trust_deleg.add_argument(
        "--not-after",
        default=None,
        help="Delegation validity end (microsecond UTC Z form); default: now + 365d "
        "(must be <= 400 days after --not-before per §5.4). Pin this together with "
        "--not-before for an idempotent re-run (see --not-before).",
    )
    trust_deleg.add_argument(
        "--max-operations",
        type=int,
        default=None,
        help="Optional cap on the number of lifecycle operations the registrar may "
        "authorise under this delegation (>= 1; default: unbounded)",
    )
    trust_deleg.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned trust-genesis JSON (or REGISTA_TRUST_GENESIS_PATH)",
    )
    # SUPPRESS (see rebuild-projection/init-log): a subparser --project/--json with a
    # None/False default would clobber the global value the top-level parser already set.
    trust_deleg.add_argument(
        "--project",
        default=argparse.SUPPRESS,
        help="Trust-log project (schema); defaults to the global --project, else the "
        "genesis document's project_name_hint (regista_trust)",
    )
    trust_deleg.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify and print the plan; write NOTHING",
    )
    trust_deleg.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output",
    )
    trust_deleg.set_defaults(func=cmd_trust_delegate_registrar)

    # WI-330: the signed estate cutover catalog (§4.3). The artifact agent-suite's
    # cutover runbook §5.4 step 4 requires and nothing could emit. `catalog` produces
    # and signs (ARCHITECTURE-0.6.0.md:942); `sign-catalog` is the airgapped k-of-n leg;
    # `verify-catalog` is step 5's check and mirrors the existing `verify-genesis` verb.
    # Publishing (§4.4 `trust publish`) is a separate, still-unimplemented command;
    # these write files and never touch git or a network.
    #
    # allow_abbrev=False on all three: argparse's prefix matching would otherwise let
    # `--project` (a global option that must appear BEFORE the subcommand) silently bind
    # to a subcommand option it happens to prefix. These are ceremony commands whose
    # arguments name key material and signed inputs, so a typo must be an error rather
    # than a guess.
    trust_catalog = trust_sub.add_parser(
        "catalog",
        help="Produce and sign the estate cutover catalog (§4.3)",
        allow_abbrev=False,
        description="Build the signed estate cutover catalog from live store state and "
        "the operator's recorded frozen-legacy measurements, and write its exact "
        "canonical JCS publication bytes. Every epoch fact is RECOMPUTED from signed "
        "event bytes and cross-checked against both the mutable posture rows and the "
        "approved preflight numbers. Publishing those bytes to the §4.2 publication "
        "clone is a separate operator step.",
    )
    trust_catalog.add_argument(
        "--inputs",
        required=True,
        help="Path to the regista.estate-catalog-inputs/v1 measurements file: one "
        "entry per project with {project, project_name_hint?, legacy_project?, "
        "legacy_head_event_hash?, legacy_event_count?, scheme_counts?, "
        "expected_new_epoch_head_event_hash, expected_new_epoch_event_count}. The two "
        "expected_* values are the approved preflight result "
        "(ARCHITECTURE-0.6.0.md:802-810) and are MANDATORY: the command must not be the "
        "only witness to the numbers it signs. Either legacy_project (to re-measure the "
        "frozen store) or all three recorded legacy values (runbook §2.4) is also "
        "required per entry; supplying both cross-checks them. This is a measurements "
        "file, NOT the catalog document — the catalog itself is never hand-authored.",
    )
    trust_catalog.add_argument(
        "--expected-estate",
        required=True,
        help="Path to the regista.estate-manifest/v1 document listing every "
        "project_instance_id a COMPLETE catalog must cover. Required: without it "
        "'complete' cannot be falsified, and a silently dropped project is the attack "
        "the catalog exists to expose (RECONCILIATION.md:682-684). Nothing is "
        "hardcoded — the estate's size is the operator's to declare.",
    )
    trust_catalog.add_argument(
        "--out", required=True, help="Path the canonical signed catalog bytes are written to"
    )
    trust_catalog.add_argument(
        "--key",
        required=True,
        action="append",
        help="Path to a ROOT authorising 32-byte Ed25519 seed (64 hex chars or base64). "
        "REPEATABLE: pass one --key per root to satisfy a k-of-n threshold in a single "
        "invocation. Each key's fingerprint must be in the verified checkpoint's "
        "active_root_fingerprints. For an airgapped ceremony, pass what you have with "
        "--incomplete-signatures and finish with `regista trust sign-catalog`.",
    )
    trust_catalog.add_argument(
        "--incomplete-signatures",
        action="store_true",
        help="Write a catalog that does NOT yet meet the root threshold, for couriering "
        "to the remaining offline roots. Such a catalog never verifies; refused by "
        "default so it is not produced by accident.",
    )
    trust_catalog.add_argument(
        "--allow-partial",
        action="store_true",
        help="Produce a catalog covering fewer projects than --expected-estate lists. "
        "It is stamped catalog_status: partial inside the signed bytes and is a "
        "ceremony FAILURE (RECONCILIATION.md:682-684), not a success. Refused by "
        "default.",
    )
    trust_catalog.add_argument(
        "--trust-checkpoint",
        required=True,
        help="Path to the PUBLISHED regista.trust-checkpoint document whose digest the "
        "catalog binds. It is reconciled against the live trust log AND authenticated "
        "(parsed, canonical-form-checked, signature-verified) against the root "
        "authority DERIVED from that same verified walk; its own "
        "active_root_fingerprints are a claim reconciled against that set, never the "
        "source of it. A local observation is not a checkpoint and is not accepted.",
    )
    trust_catalog.add_argument(
        "--trust-publication-repo",
        default=None,
        help="Root of the §4.2 publication clone containing --trust-checkpoint",
    )
    trust_catalog.add_argument(
        "--trust-publication-commit",
        default=None,
        help="Full 40-hex git commit pinned out of band for the publication channel",
    )
    trust_catalog.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned trust-genesis JSON (or REGISTA_TRUST_GENESIS_PATH)",
    )
    trust_catalog.add_argument(
        "--trust-project",
        default=None,
        help="Trust-log schema; defaults to the genesis document's signed "
        "project_name_hint (regista_trust)",
    )
    trust_catalog.add_argument(
        "--created-at",
        default=None,
        help="Override created_at (UTC Z, EXACTLY six fractional digits); default: now. "
        "Pin it to reproduce a byte-identical catalog.",
    )
    trust_catalog.add_argument(
        "--prev-commit",
        default=None,
        help="Publication-channel prev_commit (full 40-hex git commit); default null",
    )
    trust_catalog.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing --out file (refused by default). The write is atomic, "
        "so a failure leaves the previous file intact.",
    )
    trust_catalog.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and validate, print the digest the real run would produce, and "
        "write NOTHING",
    )
    # SUPPRESS (see rebuild-projection): a subparser --json/--project with a
    # False/None default would clobber the global value the top-level parser set.
    trust_catalog.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )
    trust_catalog.set_defaults(func=cmd_trust_catalog)

    trust_sign_catalog = trust_sub.add_parser(
        "sign-catalog",
        help="Offline: append root signature(s) to an existing catalog (k-of-n leg)",
        allow_abbrev=False,
        description="The airgapped leg of a k-of-n cutover ceremony. Reads a catalog "
        "document, appends one or more root signatures over its EXISTING signed core, "
        "and writes the result. Never contacts a database, never rebuilds the claim, "
        "and never writes to the publication repo.",
    )
    trust_sign_catalog.add_argument("file", help="Path to the catalog JSON to sign")
    trust_sign_catalog.add_argument(
        "--out", required=True, help="Path the newly signed canonical bytes are written to"
    )
    trust_sign_catalog.add_argument(
        "--key",
        required=True,
        action="append",
        help="Path to a ROOT 32-byte Ed25519 seed (64 hex chars or base64); repeatable. "
        "Each fingerprint must be in the verified checkpoint's active_root_fingerprints "
        "and must not already appear in the catalog.",
    )
    trust_sign_catalog.add_argument(
        "--trust-checkpoint",
        required=True,
        help="Path to the PUBLISHED trust-checkpoint the catalog binds; authenticated "
        "offline and used for the active root set and threshold",
    )
    trust_sign_catalog.add_argument(
        "--trust-log-project",
        default=None,
        help="Schema holding the estate trust log. Present it to prove a ROOT ROTATION: "
        "the log is replayed from the pinned genesis under full verification and the "
        "resulting signer set/threshold become the authority. Omit it and the authority "
        "is genesis itself (the zero-rotation state) — correct for a domain that has "
        "never rotated, and any checkpoint claiming a different root set is refused by "
        "name. There is no operator channel for root public keys by design.",
    )
    trust_sign_catalog.add_argument(
        "--trust-log-dsn",
        default=None,
        help="DSN for --trust-log-project; defaults to --dsn/REGISTA_DSN",
    )
    trust_sign_catalog.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned trust-genesis JSON (or REGISTA_TRUST_GENESIS_PATH)",
    )
    trust_sign_catalog.add_argument(
        "--force", action="store_true", help="Replace an existing --out file"
    )
    trust_sign_catalog.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )
    trust_sign_catalog.set_defaults(func=cmd_trust_sign_catalog)

    trust_verify_catalog = trust_sub.add_parser(
        "verify-catalog",
        help="Verify a published estate cutover catalog; nonzero exit on invalid",
        allow_abbrev=False,
        description="Runbook §5.4 step 5: verify a published catalog's signatures, "
        "fields, referenced checkpoint and completeness. Offline and read-only — it "
        "reads the named files and nothing else. Exit 0 = VALID (authenticated and "
        "complete); exit 3 = PARTIAL (authenticated, but the catalog declares itself a "
        "ceremony failure); exit 1 = refused.",
    )
    trust_verify_catalog.add_argument("file", help="Path to the published catalog JSON")
    trust_verify_catalog.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned trust-genesis JSON (or REGISTA_TRUST_GENESIS_PATH). "
        "REQUIRED: it is the ROOT of the authority chain — the initial signer set, "
        "threshold and public keys everything else is derived from.",
    )
    trust_verify_catalog.add_argument(
        "--trust-checkpoint",
        required=True,
        help="Path to the published trust-checkpoint document. REQUIRED: it is parsed, "
        "canonical-form-checked and signature-verified against the genesis-rooted "
        "authority, and its declared active_root_fingerprints must EQUAL that derived "
        "set. There is no mode in which this is skipped and the verdict still reads "
        "VALID.",
    )
    trust_verify_catalog.add_argument(
        "--expected-estate",
        required=True,
        help="Path to the regista.estate-manifest/v1 document listing every "
        "project_instance_id a complete catalog must cover. REQUIRED: 'complete' is a "
        "claim about a set the catalog cannot describe on its own.",
    )
    trust_verify_catalog.add_argument(
        "--trust-log-project",
        default=None,
        help="Schema holding the estate trust log. Present it to prove a ROOT ROTATION: "
        "the log is replayed from the pinned genesis under full verification and the "
        "resulting signer set/threshold become the authority. Omit it and the authority "
        "is genesis itself (the zero-rotation state) — correct for a domain that has "
        "never rotated, and any checkpoint claiming a different root set is refused by "
        "name. There is no operator channel for root public keys by design.",
    )
    trust_verify_catalog.add_argument(
        "--trust-log-dsn",
        default=None,
        help="DSN for --trust-log-project; defaults to --dsn/REGISTA_DSN",
    )
    trust_verify_catalog.add_argument(
        "--expect-digest",
        default=None,
        help="estate_catalog_digest obtained by direct exchange. Without it the check "
        "proves internal coherence only, never that the first publication was honest.",
    )
    trust_verify_catalog.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )
    trust_verify_catalog.set_defaults(func=cmd_trust_verify_catalog)

    # WI-325: `genesis init` — open an ordinary project's clean v6 epoch. The
    # per-project analog of `trust init-log`. Verify-before-touch, accurate --dry-run,
    # no --force (a second genesis would fork the project's identity).
    genesis_parser = subs.add_parser(
        "genesis", help="Per-project v6 epoch genesis (EPOCH-RESET §5)"
    )
    genesis_sub = genesis_parser.add_subparsers(dest="subcommand")
    genesis_init = genesis_sub.add_parser(
        "init",
        help="Open this project's clean v6 epoch: assemble, verify against the live "
        "trust log, and write the single project_initialized genesis event",
    )
    genesis_init.add_argument(
        "--principal",
        required=True,
        help="Canonical kind:subject principal id that signs the genesis; must have a "
        "live, ACTIVE principal_key_enrolled in the trust log and its private key in "
        "this host's keyset (e.g. agent:example-host)",
    )
    genesis_init.add_argument(
        "--gate-report",
        default=None,
        help="Path to the `agent-suite genesis-gate --json` report. REQUIRED: "
        "EPOCH-RESET §5 makes the gate a precondition on the first write, so "
        "gate_passed is never asserted without evidence that PASSES and is bound to "
        "this store fingerprint and project. There is no override.",
    )
    genesis_init.add_argument(
        "--genesis",
        default=None,
        help="Path to the pinned, published trust-genesis JSON (or "
        "REGISTA_TRUST_GENESIS_PATH)",
    )
    genesis_init.add_argument(
        "--trust-project",
        default=None,
        help="Trust-log schema to verify the reference against; defaults to the "
        "genesis document's signed project_name_hint (regista_trust)",
    )
    genesis_init.add_argument(
        "--key-id",
        default=None,
        help="Sign with this specific enrolled key_id; required only when the "
        "principal has more than one active enrolled key",
    )
    genesis_init.add_argument(
        "--trust-event-hash",
        default=None,
        help="Assert the principal_key_enrolled event hash the acceptance will name. "
        "Optional; when given it is VERIFIED against the trust log, never trusted",
    )
    genesis_init.add_argument(
        "--trust-domain-id",
        default=None,
        help="Assert the trust domain being joined. Optional; verified against the "
        "pinned genesis document",
    )
    genesis_init.add_argument(
        "--trust-checkpoint",
        default=None,
        help="Path to a PUBLISHED regista.trust-checkpoint document to reference. When "
        "omitted, a local unsigned observation of the live trust log is derived instead "
        "and reported as source=derived",
    )
    genesis_init.add_argument(
        "--trust-publication-repo",
        help="Root of the clean §4.2 publication clone containing --trust-checkpoint",
    )
    genesis_init.add_argument(
        "--trust-publication-commit",
        help="Full git commit pinned out of band for the checkpoint publication channel",
    )
    genesis_init.add_argument(
        "--checkpoint-seq",
        type=int,
        default=1,
        help="checkpoint_seq for a DERIVED checkpoint (default 1; §5.8 requires >= 1). "
        "Ignored when --trust-checkpoint supplies a published document",
    )
    genesis_init.add_argument(
        "--project-instance-id",
        default=None,
        help="UUID to use as the project_instance_id; a fresh UUID4 by default. This "
        "value is permanent — it is the project's identity",
    )
    genesis_init.add_argument(
        "--scope-entity-kind",
        action="append",
        default=None,
        help="An entity kind the bootstrap key's acceptance authorises; repeatable and "
        "comma-joinable. Default: project,principal,workflow,work_item. 'project' is "
        "mandatory — without it the acceptance does not authorise its own genesis",
    )
    genesis_init.add_argument(
        "--may-sign-bundles",
        action="store_true",
        help="Grant may_sign_bundles in the bootstrap acceptance (default: false). "
        "may_accept_keys and may_sign_checkpoints are always true — the writer "
        "requires both",
    )
    # SUPPRESS (see rebuild-projection/init-log): a subparser --project/--json with a
    # None/False default would clobber the global value the top-level parser already set.
    genesis_init.add_argument(
        "--project",
        default=argparse.SUPPRESS,
        help="Project (schema) whose epoch is being opened; defaults to the global "
        "--project / REGISTA_PROJECT",
    )
    genesis_init.add_argument(
        "--dry-run",
        action="store_true",
        help="Run every check — gate evidence, store probe, live trust-log "
        "verification, key resolution, envelope assembly — and write NOTHING",
    )
    genesis_init.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="JSON output"
    )
    genesis_init.set_defaults(func=cmd_genesis_init)

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
