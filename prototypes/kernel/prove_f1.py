"""Reintroduce defects in temporary copies and require assertion failures.

Run with REGISTA_TEST_DSN set, using the same interpreter as the test suite.
No production source is edited. JUnit distinguishes test-body failures from
setup errors and skipped tests. An unmodified control run is required first.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
TESTS = ROOT / "tests"


def replace_once(before: str, after: str) -> Callable[[str], str]:
    def change(source: str) -> str:
        if before not in source:
            raise AssertionError(f"mutation anchor disappeared: {before!r}")
        return source.replace(before, after, 1)

    return change


def body(name: str, replacement: str) -> Callable[[str], str]:
    def change(source: str) -> str:
        tree = ast.parse(source)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
        lines = source.splitlines(keepends=True)
        indent = " " * (node.col_offset + 4)
        end = node.end_lineno
        assert end is not None
        lines[node.body[0].lineno - 1 : end] = [
            indent + line + "\n" for line in replacement.splitlines()
        ]
        return "".join(lines)

    return change


def method_replace(name: str, before: str, after: str) -> Callable[[str], str]:
    def change(source: str) -> str:
        tree = ast.parse(source)
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
        lines = source.splitlines(keepends=True)
        end = node.end_lineno
        assert end is not None
        segment = "".join(lines[node.lineno - 1:end])
        changed = replace_once(before, after)(segment)
        return "".join(lines[:node.lineno - 1]) + changed + "".join(lines[end:])

    return change


def fencing(source: str) -> str:
    start = source.index("            # Lease fencing, before")
    end = source.index("            if expected_seq is not None", start)
    return source[:start] + source[end:]


def sequence_before_fencing(source: str) -> str:
    start = source.index('            if expected_seq is not None and expected_seq !=')
    end = source.index('            wf = self._read_workflow', start)
    check = source[start:end]
    changed = source[:start] + source[end:]
    barrier = changed.index('            # Lease fencing, before')
    return changed[:barrier] + check + changed[barrier:]


def nonatomic(source: str) -> str:
    start = source.index("    def _append_event(")
    end = source.index("    # ---- links", start)
    segment = source[start:end]
    segment = segment.replace(
        '        cur.execute(\n            "SELECT payload_hash',
        '        self._conn.commit()\n        cur.execute(\n            "SELECT payload_hash',
        1,
    )
    segment = segment.replace(
        "        return event_id", "        self._conn.commit()\n        return event_id"
    )
    return source[:start] + segment + source[end:]


def materialize(source: str) -> str:
    source = source.replace(
        'self._conn.cursor(name="kernel_replay") as rows', "self._conn.cursor() as rows"
    )
    source = source.replace("                rows.itersize = 64\n", "")
    return source.replace(
        "                for i, r in enumerate(rows):",
        "                for i, r in enumerate(rows.fetchall()):",
    )


# Each selector names assertions the corresponding defect MUST kill.
MUTANTS: list[tuple[str, str, Callable[[str], str], str]] = [
    (
        "cli_show_workflow_hidden", "cli.py",
        replace_once('        print(f"  workflow {item.workflow_name} v{item.workflow_version}")',
                     "        pass"),
        "test_each_command[False-show]",
    ),
    (
        "cli_list_workflow_hidden", "cli.py",
        replace_once('f"{i.workflow_name} v{i.workflow_version}{mark}"', 'f"{mark}"'),
        "test_each_command[False-list]",
    ),
    (
        "event_sequence_constraint_removed", "schema.sql",
        replace_once(
            "occurred_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),\n"
            "    UNIQUE (work_item_id, event_seq)",
            "occurred_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()",
        ),
        "test_event_sequence_constraint",
    ),
    (
        "json_key_order_not_canonical", "kernel.py",
        replace_once("obj, sort_keys=True, separators=", "obj, sort_keys=False, separators="),
        "test_replay_key_order_is_irrelevant",
    ),
    (
        "legacy_document_keys_accepted", "kernel.py",
        body("validate_workflow_document", "return ()"),
        "test_legacy_document_keys_fail_closed",
    ),
    (
        "history_order_reversed", "kernel.py",
        replace_once('sql.append("ORDER BY event_seq LIMIT %s")',
                     'sql.append("ORDER BY event_seq DESC LIMIT %s")'),
        "test_history_cursor_windows",
    ),
    (
        "database_clock_replaced", "kernel.py",
        body("_db_now", "return datetime.fromtimestamp(0).astimezone()"),
        "test_stamps_use_one_database_instant",
    ),
    (
        "open_existing_gate_removed", "kernel.py",
        replace_once("if require_existing:", "if False:"),
        "test_open_existing_refuses_without_writes",
    ),
    (
        "cli_existing_gate_removed", "cli.py",
        replace_once('require_existing=args.command != "init"', 'require_existing=False'),
        "test_cli_inspection_requires_existing",
    ),
    ("lease_fencing", "kernel.py", fencing, "test_transition_fencing"),
    (
        "heartbeat_owner_attempt_expiry",
        "kernel.py",
        replace_once(
            '"WHERE work_item_id = %s AND actor_id = %s AND attempt_number = %s "\n'
            '                "AND expires_at > clock_timestamp() "',
            '"WHERE work_item_id = %s AND %s IS NOT NULL AND %s IS NOT NULL "',
        ),
        "test_heartbeat_refusals",
    ),
    (
        "claim_contention",
        "kernel.py",
        replace_once('if existing and existing["live"]:', "if False:"),
        "test_claim_contested or test_concurrent_claim_one_winner",
    ),
    (
        "attempt_reissued",
        "kernel.py",
        replace_once("last_attempt = last_attempt + 1", "last_attempt = 1"),
        "test_attempt_monotonic",
    ),
    ("release_ignored", "kernel.py", body("release", "return"), "test_claim_acquire_release"),
    (
        "heartbeat_no_extension",
        "kernel.py",
        replace_once(
            'clock_timestamp() + make_interval(secs => %s) "\n                "WHERE work_item_id',
            'expires_at + make_interval(secs => %s * 0) "\n                "WHERE work_item_id',
        ),
        "test_heartbeat_extension",
    ),
    (
        "sweep_live_leases",
        "kernel.py",
        replace_once(
            "DELETE FROM claims WHERE expires_at <= clock_timestamp()",
            "DELETE FROM claims WHERE expires_at > clock_timestamp()",
        ),
        "test_sweep_scoped_and_live_safe or test_sweep_preserves_replacement_lease",
    ),
    (
        "retry_conflict_accepted",
        "kernel.py",
        replace_once('if bytes(prior["request_hash"]) != request_hash:', "if False:"),
        "test_idempotency_conflict",
    ),
    (
        "retry_returns_latest",
        "kernel.py",
        replace_once("state, fields, target_seq,", "state, fields, target_seq + 1,"),
        "test_idempotency_original_result",
    ),
    ("partial_commit", "kernel.py", nonatomic, "test_event_projection_atomicity"),
    (
        "search_path_injection",
        "kernel.py",
        lambda s: s.replace("Identifier(schema)", "SQL(schema)").replace(
            "Identifier(self._schema)", "SQL(self._schema)"
        ),
        "test_supplied_schema_cannot_redirect",
    ),
    (
        "namespace_shared",
        "kernel.py",
        replace_once('schema: str = "public",', 'schema: str = "public",'),
        "test_namespace_isolation",
    ),
    (
        "type_unchecked",
        "kernel.py",
        replace_once("if type not in wf.types:", "if False:"),
        "test_create_refusals[type]",
    ),
    (
        "workflow_ignored",
        "kernel.py",
        replace_once(
            "self._read_workflow(cur, workflow, workflow_version)",
            'self._read_workflow(cur, "review", workflow_version)',
        ),
        "test_create_refusals[workflow]",
    ),
    (
        "role_gate_removed",
        "kernel.py",
        replace_once("if allowed and (role is None or role not in allowed):", "if False:"),
        "test_transition_refusals[role]",
    ),
    (
        "required_gate_removed",
        "kernel.py",
        replace_once("if missing or nulled:", "if False:"),
        "test_transition_refusals[required] or test_transition_refusals[null] "
        "or test_clear_refusals[required_clear] or test_generic_review_note_and_mixed_actors",
    ),
    (
        "terminal_gate_removed",
        "kernel.py",
        replace_once("if state in wf.terminal:", "if False:"),
        "test_transition_refusals[terminal]",
    ),
    (
        "from_state_gate_removed",
        "kernel.py",
        replace_once("if state not in froms:", "if False:"),
        "test_transition_refusals[wrong_state]",
    ),
    (
        "reserved_payload_allowed",
        "kernel.py",
        replace_once("if reserved:", "if False:"),
        "test_reserved_payload_refusal",
    ),
    (
        "field_schema_unenforced",
        "kernel.py",
        body("_validate_fields", "return"),
        "test_declared_field_refusals or "
        "test_work_item_refs and (missing or wrong_type or invalid_uuid)",
    ),
    ("json_types_unchecked", "kernel.py", body("_check_json", "return"), "test_json_type_refusal"),
    (
        "clear_collision_allowed",
        "kernel.py",
        replace_once("if contradictory:", "if False:"),
        "test_clear_refusals[same_key]",
    ),
    (
        "clear_not_recorded",
        "kernel.py",
        replace_once('reduced["unset"] = list(unset)', 'reduced["unset"] = []'),
        "test_shallow_merge_and_atomic_clear",
    ),
    (
        "expected_sequence_ignored",
        "kernel.py",
        replace_once(
            'if expected_seq is not None and expected_seq != int(item["last_event_seq"]):',
            "if False:",
        ),
        "test_expected_sequence[1] or test_expected_sequence[99]",
    ),
    (
        "schema_refusal_removed",
        "kernel.py",
        lambda s: s.replace("raise UnsupportedSchemaError(", "raise KernelError("),
        "test_initialize_refuses_without_writes",
    ),
    (
        "workflow_semantics_unchecked",
        "kernel.py",
        body("validate", "return"),
        "test_document_semantic_refusals and (unreachable or unknown_from or unknown_to "
        "or undeclared_role or unused_role) or test_field_declaration_refusals",
    ),
    (
        "workflow_pinning_removed",
        "kernel.py",
        replace_once(
            'self._read_workflow(cur, item["workflow_name"], item["workflow_version"])',
            'self._read_workflow(cur, item["workflow_name"], None)',
        ),
        "test_version_pinning",
    ),
    (
        "link_self_allowed",
        "kernel.py",
        replace_once('raise InvalidFieldError("a work item cannot link to itself")', "return"),
        "test_link_refusals[self]",
    ),
    (
        "link_type_unchecked",
        "kernel.py",
        replace_once(
            "if wf.link_type_names is not None and link_type not in wf.link_type_names:",
            "if False:",
        ),
        "test_link_vocabulary_and_removal",
    ),
    (
        "link_endpoints_unchecked",
        "kernel.py",
        replace_once('raise InvalidFieldError(f"link source does not exist: {source}")', "return"),
        "test_link_refusals[missing_source]",
    ),
    (
        "query_limits_ignored",
        "kernel.py",
        body("_check_limit", "return limit"),
        "test_query_refusals[zero] or test_query_refusals[too_large]",
    ),
    (
        "nested_filter_allowed",
        "kernel.py",
        body("_check_where_fields", "return where_fields"),
        "test_query_refusals[nested_filter] or test_query_refusals[too_many_filters]",
    ),
    (
        "bad_direction_allowed",
        "kernel.py",
        body("_check_direction", "return direction"),
        "test_query_refusals[direction]",
    ),
    (
        "unknown_satisfaction_allowed",
        "kernel.py",
        body("_check_known_states", "return"),
        "test_query_refusals[satisfied]",
    ),
    ("replay_materialized", "kernel.py", materialize, "test_replay_memory_bound"),
    (
        "snapshot_read_committed",
        "kernel.py",
        replace_once(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
        ),
        "test_replay_repeatable_snapshot",
    ),
    (
        "prepared_cache_restored",
        "kernel.py",
        replace_once('"prepare_threshold": None', '"prepare_threshold": 5'),
        "test_sustained_pool_operations",
    ),
    (
        "cli_failures_exit_zero",
        "cli.py",
        replace_once(
            "    sys.exit(main())",
            "    try:\n        main()\n    except SystemExit:\n        pass\n    sys.exit(0)",
        ),
        "test_cli_refusal_audit or test_cli_drift_nonzero",
    ),
]

MUTANTS.extend(
    [
        (
            "document_rules_ignored",
            "kernel.py",
            body("validate_workflow_document", "return ()"),
            "test_document_semantic_refusals",
        ),
        (
            "invalid_files_accepted",
            "kernel.py",
            body(
                "load_workflow",
                "return Workflow(name='mutant', states=('new',), initial='new', "
                "transitions={}, types=('task',))",
            ),
            "test_load_refusals",
        ),
        (
            "workflow_version_assertion_ignored",
            "kernel.py",
            body("_assert_version", "return"),
            "test_workflow_version_conflict",
        ),
        (
            "workflow_duplicate_version",
            "kernel.py",
            replace_once('if row and bytes(row["content_hash"]) == content_hash:', "if False:"),
            "test_workflow_idempotent",
        ),
        (
            "replay_always_clean",
            "kernel.py",
            body("replay", "return ('', {}, [])"),
            "test_replay_detects_damage or test_cli_drift_nonzero "
            "or test_scoped_replay_ignores_other_damage",
        ),
        (
            "absent_link_removal_silent",
            "kernel.py",
            replace_once("if cur.rowcount == 0:", "if False:"),
            "test_remove_absent_link",
        ),
        (
            "missing_target_silent",
            "kernel.py",
            replace_once(
                'raise InvalidFieldError(f"link target does not exist: {target}")', "return"
            ),
            "test_link_refusals[missing_target]",
        ),
        (
            "dead_cursor_restarts",
            "kernel.py",
            body("_after_key", "return (self._db_now(cur), after)"),
            "test_query_refusals[dead_cursor]",
        ),
        (
            "empty_states_allowed",
            "kernel.py",
            replace_once("if not states:", "if False:"),
            "test_query_refusals[empty_states]",
        ),
        (
            "unknown_transition_accepted",
            "kernel.py",
            replace_once(
                "            if transition not in wf.transitions:",
                '            if transition == "typo":\n                transition = "start"\n'
                "            if transition not in wf.transitions:",
            ),
            "test_transition_refusals[unknown]",
        ),
        (
            "workflow_name_ignored",
            "kernel.py",
            replace_once(
                "self._read_workflow(cur, workflow, workflow_version)",
                'self._read_workflow(cur, "review", workflow_version)',
            ),
            "test_supplied_workflow_name_is_data",
        ),
        (
            "transition_releases_lease",
            "kernel.py",
            replace_once(
                '            state = item["current_state"]',
                '            cur.execute("DELETE FROM claims WHERE work_item_id = %s", '
                "(work_item_id,))\n"
                '            state = item["current_state"]',
            ),
            "test_lease_is_retained_until_explicit_release",
        ),
        (
            "cli_bad_exits_zero",
            "cli.py",
            replace_once(
                "    sys.exit(main())",
                "    try:\n        main()\n    except SystemExit:\n        pass\n    sys.exit(0)",
            ),
            "test_cli_unlink or test_cli_unreachable_database",
        ),
    ]
)

MUTANTS.extend(
    [
        ("namespace_shared_role", "kernel.py", lambda s: s, "test_database_role_is_scoped"),
        (
            "expected_sequence_always_refused",
            "kernel.py",
            replace_once(
                'if expected_seq is not None and expected_seq != int(item["last_event_seq"]):',
                "if expected_seq is not None:",
            ),
            "test_expected_sequence[0]",
        ),
    ]
)

MUTANTS.extend(
    [
        (
            "retry_lookup_removed",
            "kernel.py",
            body("_idempotency_result", "return None"),
            "test_concurrent_idempotency or test_idempotency_original_result",
        ),
        (
            "sequence_gaps",
            "kernel.py",
            replace_once(
                'seq = int(item["next_event_seq"])', 'seq = int(item["next_event_seq"]) + 1'
            ),
            "test_concurrent_gap_free",
        ),
        (
            "release_fence_removed",
            "kernel.py",
            body(
                "release",
                'self._conn.execute("DELETE FROM claims WHERE work_item_id = %s", '
                "(work_item_id,))\n"
                "self._conn.commit()",
            ),
            "test_attempt_monotonic",
        ),
        (
            "initializer_missing",
            "kernel.py",
            body("initialize", "return"),
            "test_concurrent_initialize",
        ),
        (
            "workflow_lock_missing",
            "kernel.py",
            body("_transaction_lock", "return"),
            "test_concurrent_workflow_registration",
        ),
    ]
)

MUTANTS.append(
    (
        "write_schema_gate_removed",
        "kernel.py",
        body("_require_writable_schema", "return"),
        "test_unsupported_schema_cannot_write",
    )
)

MUTANTS.extend(
    [
        (
            "missing_dsn_exit_one",
            "cli.py",
            replace_once(
                'raise KernelError("no DSN: pass --dsn or set REGISTA_DSN")',
                'raise SystemExit("no DSN: pass --dsn or set REGISTA_DSN")',
            ),
            "test_cli_missing_dsn",
        ),
        (
            "append_writer_reintroduced",
            "kernel.py",
            lambda s: s + "\nKernel.append_event = lambda *args, **kwargs: None\n",
            "test_transition_is_the_only_public_event_writer",
        ),
    ]
)

MUTANTS.append(
    ("invalid_ttl_allowed", "kernel.py", body("_check_ttl", "return"), "test_invalid_lease_ttl")
)

MUTANTS.extend(
    [
        (
            "cli_success_exits_one",
            "cli.py",
            lambda source: source.replace("    return 0", "    return 1").replace(
                "return 1 if drift else 0", "return 1 if drift else 1"
            ),
            "test_each_command or test_cli_fresh_init or test_cli_new_workflow "
            "or test_cli_listing_modes_and_pages or test_cli_unlink",
        ),
        (
            "replay_resets_fencing",
            "kernel.py",
            replace_once(
                '            )\n        return (state, fields, drift)\n',
                '            )\n'
                '        self._conn.execute("UPDATE claim_attempts SET last_attempt=0")\n'
                '        self._conn.commit()\n'
                '        return (state, fields, drift)\n',
            ),
            "test_replay_clean_and_boundary",
        ),
        (
            "duplicate_link_refused",
            "kernel.py",
            replace_once('"ON CONFLICT DO NOTHING"', '""'),
            "test_links_lookup_and_idempotency",
        ),
        (
            "query_order_reversed",
            "kernel.py",
            replace_once(
                "ORDER BY w.created_at, w.work_item_id LIMIT %s",
                "ORDER BY w.created_at DESC, w.work_item_id DESC LIMIT %s",
            ),
            "test_query_order_and_paging or test_query_filters_and_liveness "
            "or test_d6_single_hop_no_scheduler",
        ),
        (
            "initializer_missing_catalog",
            "kernel.py",
            body("initialize", "return"),
            "test_catalog_roundtrip",
        ),
        (
            "history_missing",
            "kernel.py",
            body("history", "return []"),
            "test_create_and_get or test_history_cursor_windows",
        ),
        (
            "replay_ignores_handoff_fields",
            "kernel.py",
            replace_once('fields.update(payload.get("fields", {}))', "pass"),
            "test_full_repair_handoff",
        ),
        (
            "replay_writes",
            "kernel.py",
            replace_once(
                '        self._conn.rollback()  # isolation applies to a fresh transaction',
                '        self._conn.execute("UPDATE work_items_current SET '
                'current_state=current_state")\n'
                '        self._conn.commit()\n'
                '        self._conn.rollback()  # isolation applies to a fresh transaction',
            ),
            "test_replay_read_only_no_temp_residue",
        ),
        (
            "cli_connect_outside_error_handler",
            "cli.py",
            replace_once(
                "    k: Kernel | None = None\n    try:\n        k = _kernel(args)\n",
                "    k: Kernel | None = _kernel(args)\n    try:\n",
            ),
            "test_cli_unreachable_database",
        ),
    ]
)


MUTANTS.extend(
    [
        (
            "expected_sequence_gt", "kernel.py",
            replace_once(
                'expected_seq != int(item["last_event_seq"])',
                'expected_seq > int(item["last_event_seq"])',
            ),
            "test_expected_sequence_stale_lower",
        ),
        (
            "lease_subtype_erased", "kernel.py",
            lambda source: source.replace("return LeaseNotHeldError(", "return StaleAttemptError("),
            "test_transition_fencing[actor] or test_transition_fencing[released] "
            "or test_transition_fencing[swept] or test_heartbeat_refusals[actor]",
        ),
        (
            "replay_chain_check_removed", "kernel.py",
            replace_once("if stored != running:", "if False:"),
            "test_replay_detects_damage[chain] or test_cli_chain_break_nonzero",
        ),
        (
            "inlock_retry_recheck_removed", "kernel.py",
            replace_once(
                'self._transaction_lock(cur, "idempotency", idempotency_key)\n'
                '                prior = self._idempotency_result('
                'cur, idempotency_key, request_hash)',
                'self._transaction_lock(cur, "idempotency", idempotency_key)\n'
                '                prior = None',
            ),
            "test_idempotency_recheck_under_item_lock",
        ),
        (
            "single_sequence_number_skipped", "kernel.py",
            replace_once(
                'seq = int(item["next_event_seq"])',
                'seq = int(item["next_event_seq"]) + (int(item["next_event_seq"]) == 2)',
            ),
            "test_concurrent_gap_free",
        ),
        (
            "heartbeat_item_lock_removed", "kernel.py",
            method_replace("heartbeat", '"FOR UPDATE",', '"",'),
            "test_heartbeat_serializes_before_expiry_check",
        ),
        (
            "public_writer_unclassified", "kernel.py",
            lambda source: source + '\n    def unclassified_write(self):\n'
            '        self._conn.execute("DELETE FROM claims")\n',
            "test_public_methods_declare_access_and_gate_writes",
        ),
        (
            "public_writer_declared_read", "kernel.py",
            replace_once(
                '@_pooled_operation(access="write")\n    def transition(',
                '@_pooled_operation(access="read")\n    def transition(',
            ),
            "test_public_methods_declare_access_and_gate_writes",
        ),
        (
            "invalid_utf8_traceback_restored", "kernel.py",
            replace_once(
                "json.JSONDecodeError, UnicodeDecodeError, OSError",
                "json.JSONDecodeError, OSError",
            ),
            "test_cli_invalid_utf8_workflow",
        ),
        (
            "sequence_before_lease_fencing", "kernel.py", sequence_before_fencing,
            "test_fencing_precedes_sequence",
        ),
    ]
)


def run(root: Path, selection: str, report: Path) -> tuple[int, list[str], list[str], str]:
    env = {**os.environ, "REGISTA_KERNEL_TEST_ROOT": str(root)}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(TESTS), "-q", "-k", selection, f"--junitxml={report}"],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    tree = ET.parse(report)
    failed, other = [], []
    for case in tree.iter("testcase"):
        node = case.attrib["classname"] + "::" + case.attrib["name"]
        if case.find("failure") is not None:
            failed.append(node)
        else:
            other.append(node)
    return result.returncode, failed, other, result.stdout + result.stderr


def main() -> int:
    if not os.environ.get("REGISTA_TEST_DSN"):
        raise SystemExit("REGISTA_TEST_DSN is required; use only disposable PostgreSQL")
    evidence: list[dict[str, Any]] = []
    selected = MUTANTS
    if len(sys.argv) > 1:
        selected = [m for m in MUTANTS if m[0] in sys.argv[1:]]
        if not selected:
            raise SystemExit("no such mutant")
    with tempfile.TemporaryDirectory(prefix="regista-f1-proof-") as directory:
        scratch = Path(directory)
        control_code, _, _, output = run(
            ROOT, "not test_replay_memory_bound", scratch / "control.xml"
        )
        if control_code != 0:
            print(output)
            raise SystemExit("unmodified control failed; no mutation evidence is valid")
        for name, filename, change, selection in selected:
            for path in ROOT.iterdir():
                if path.is_file() and path.suffix in (".py", ".json", ".sql", ".yaml"):
                    shutil.copy2(path, scratch / path.name)
            original = (scratch / filename).read_text()
            changed = change(original)
            if name.startswith("namespace_shared"):
                changed = original
                changed = changed.replace(
                    "        handle = cls(\n            pool,\n            schema,",
                    "        global _F1_FIRST_SCHEMA\n"
                    "        if '_F1_FIRST_SCHEMA' not in globals():\n"
                    "            _F1_FIRST_SCHEMA = schema\n"
                    "        handle = cls(\n            pool,\n            _F1_FIRST_SCHEMA,",
                )
            if changed == original:
                raise AssertionError(f"{name}: mutation changed nothing")
            (scratch / filename).write_text(changed)
            if filename.endswith(".py"):
                ast.parse(changed)
            code, failed, other, output = run(scratch, selection, scratch / "mutant.xml")
            if code != 1 or not failed or other:
                print(output)
                raise SystemExit(
                    f"{name}: need assertion failures for EVERY selected test; "
                    f"code={code}, other={other}"
                )
            print(f"KILLED {name}: {len(failed)} assertions", flush=True)
            evidence.append(
                {"mutant": name, "file": filename, "selection": selection, "failed_nodes": failed}
            )
    if len(sys.argv) == 1:
        (ROOT / "F1-mutation-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    proved = {n for e in evidence for n in e["failed_nodes"]}
    print(f"{len(evidence)} mutants killed; {len(proved)} distinct test nodes proved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
