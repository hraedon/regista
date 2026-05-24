from __future__ import annotations

import hmac as _hmac
import uuid
from datetime import datetime

import psycopg
import structlog
from psycopg.sql import SQL, Identifier

from ._datetime_utils import ts_equal as _ts_equal
from ._datetime_utils import ts_equal_within as _ts_equal_within
from ._errors import ErrorCode, SubstrateError
from ._keys import KeySet
from ._signing import verify_event
from ._signing_scheme import get_scheme
from ._types import ReplayReport

log = structlog.get_logger()


def drop_old_replay_tables(conn: psycopg.Connection, schema: str) -> None:
    """Drop stale replay tables from previous runs."""
    old_tables = conn.execute(
        SQL(
            "SELECT tablename FROM pg_tables WHERE schemaname = %s "
            "AND (tablename LIKE 'work_items_current_replay_%%' "
            "OR tablename LIKE 'replay_report_%%')"
        ),
        [schema],
    ).fetchall()
    for tbl in old_tables:
        conn.execute(SQL("DROP TABLE IF EXISTS {}").format(Identifier(tbl["tablename"])))


# AC-28: event hash chain verification (BC-233)
def _verify_hash_chain(
    event: dict,
    prev_event: dict | None,
) -> tuple[bool, str]:
    expected = event.get("prev_event_hash")
    if expected is None:
        return True, ""
    if prev_event is None:
        return False, "prev_event_hash set but no previous event"
    prev_env = prev_event.get("canonical_envelope")
    prev_sig = prev_event.get("signature")
    if prev_env is None or prev_sig is None:
        return False, "previous event missing canonical_envelope or signature"
    import hashlib

    computed = hashlib.sha256(
        bytes(prev_env) + bytes(prev_sig)
    ).digest()
    if not _hmac.compare_digest(computed, bytes(expected)):
        detail = (
            f"hash chain mismatch: computed={computed.hex()} "
            f"expected={bytes(expected).hex()}"
        )
        return False, detail
    return True, ""


class _ReplayHaltError(SubstrateError):
    def __init__(self, message: str) -> None:
        super().__init__(ErrorCode.REPLAY_HALTED, message)

_EVENT_FIELDS = (
    "event_id, work_item_id, event_seq, global_seq, actor_id, actor_kind, "
    "actor_metadata, key_id, workflow_name, workflow_version, "
    "timestamp, transition, payload, payload_canonical_hash, signature, "
    "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash"
)


def replay(
    conn: psycopg.Connection,
    schema: str,
    project: str,
    key_set: KeySet,
    continue_on_revoked: bool = False,
    verify_timestamps: bool = False,
) -> ReplayReport:
    import uuid as _uuid

    tag = _uuid.uuid4().hex[:8]
    replay_table = f"work_items_current_replay_{tag}"
    report_table = f"replay_report_{tag}"

    conn.execute(
        SQL(
            "CREATE TABLE {} AS SELECT * FROM work_items_current WHERE 1=0"
        ).format(Identifier(replay_table))
    )
    conn.execute(
        SQL(
            "CREATE TABLE {} ("
            "work_item_id UUID PRIMARY KEY, "
            "category TEXT NOT NULL, "
            "detail TEXT, "
            "warnings INTEGER NOT NULL DEFAULT 0)"
        ).format(Identifier(report_table))
    )

    wi_rows = conn.execute(
        SQL("SELECT work_item_id FROM work_items_current ORDER BY work_item_id")
    ).fetchall()

    wi_ids = {row["work_item_id"] for row in wi_rows}

    ok_count = 0
    drift_count = 0
    halted_count = 0
    total_warnings = 0

    all_events = conn.execute(
        SQL(
            f"SELECT {_EVENT_FIELDS} FROM events ORDER BY work_item_id, event_seq"
        ),
    ).fetchall()

    events_by_wi: dict = {}
    for evt in all_events:
        wid = evt["work_item_id"]
        events_by_wi.setdefault(wid, []).append(evt)

    orphan_events = set(events_by_wi.keys()) - wi_ids
    for orphan_id in orphan_events:
        orphan_evts = events_by_wi[orphan_id]
        is_created = len(orphan_evts) > 0 and orphan_evts[0]["transition"] == "created"
        if not is_created:
            halted_count += 1
            log.error(
                "replay.orphan_events",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [orphan_id, "halted", "Orphaned events with no work_item and no created event", 0],
            )
        else:
            total_warnings += 1
            log.warning(
                "replay.orphan_work_item",
                work_item_id=str(orphan_id),
                event_count=len(orphan_evts),
            )

    for row in wi_rows:
        wi_id = row["work_item_id"]
        events = events_by_wi.get(wi_id, [])

        if not events:
            continue

        try:
            replayed_state, wi_warnings = _replay_work_item(
                conn, wi_id, events, key_set, continue_on_revoked,
            )
            total_warnings += wi_warnings
        except _ReplayHaltError as e:
            halted_count += 1
            log.error("replay.halted", work_item_id=str(wi_id), error=str(e))
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [wi_id, "halted", str(e), 0],
            )
            continue
        except Exception as e:
            halted_count += 1
            log.error(
                "replay.unexpected_error",
                work_item_id=str(wi_id), error=str(e), exc_info=True,
            )
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [wi_id, "halted", f"unexpected: {e}", 0],
            )
            continue

        live_row = conn.execute(
            SQL(
            "SELECT work_item_id, workflow_name, workflow_version, work_item_type, "
            "current_state, custom_fields, needs_review, not_before, "
            "last_event_seq, last_event_at, next_event_seq, "
            "claimed_by, claim_expires_at, attempt_number "
            "FROM work_items_current WHERE work_item_id = %s"
            ),
            [wi_id],
        ).fetchone()

        if _states_match(replayed_state, live_row):
            ok_count += 1
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, warnings) VALUES (%s, %s, %s)"
                ).format(Identifier(report_table)),
                [wi_id, "replayed_ok", wi_warnings],
            )
        else:
            drift_count += 1
            diff_fields = _diff_fields(replayed_state, live_row)
            detail = (
                f"drift in: {', '.join(diff_fields)}. "
                f"live state={live_row['current_state']!r} "
                f"seq={live_row['last_event_seq']}, "
                f"replayed state={replayed_state['current_state']!r} "
                f"seq={replayed_state['last_event_seq']}"
            )
            conn.execute(
                SQL(
                    "INSERT INTO {} (work_item_id, category, detail, warnings) "
                    "VALUES (%s, %s, %s, %s)"
                ).format(Identifier(report_table)),
                [wi_id, "replayed_drift", detail, wi_warnings],
            )

        conn.execute(
            SQL(
                "INSERT INTO {} (work_item_id, workflow_name, workflow_version, "
                "work_item_type, current_state, custom_fields, needs_review, "
                "not_before, last_event_seq, last_event_at, next_event_seq, "
                "claimed_by, claim_expires_at, attempt_number) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ).format(Identifier(replay_table)),
            [
                wi_id,
                live_row["workflow_name"],
                live_row["workflow_version"],
                live_row["work_item_type"],
                replayed_state["current_state"],
                psycopg.types.json.Jsonb(replayed_state["custom_fields"]),
                replayed_state["needs_review"],
                replayed_state["not_before"],
                replayed_state["last_event_seq"],
                None,
                replayed_state["last_event_seq"] + 1,
                replayed_state["claimed_by"],
                replayed_state["claim_expires_at"],
                replayed_state["attempt_number"],
            ],
        )

    if verify_timestamps:
        from ._timestamping import TSAConfig, compute_merkle_root, verify_tsa_token

        batch_rows = conn.execute(
            "SELECT first_global_seq, last_global_seq, merkle_root, tsa_token "
            "FROM tsp_batches WHERE status = 'confirmed'"
        ).fetchall()

        event_ids_by_global_seq: dict[int, uuid.UUID] = {
            evt["global_seq"]: evt["event_id"] for evt in all_events
        }

        _verify_cfg = TSAConfig(tsa_url="")
        covered: set[int] = set()
        for br in batch_rows:
            first_seq = br["first_global_seq"]
            last_seq = br["last_global_seq"]
            for seq in range(first_seq, last_seq + 1):
                covered.add(seq)

            stored_root = bytes(br["merkle_root"]) if br["merkle_root"] else None
            tsa_token = bytes(br["tsa_token"]) if br["tsa_token"] else None

            # Re-derive the Merkle root from the current event log and compare
            # against what the TSA actually signed. This is the load-bearing
            # tamper check — without it, a forger who leaves merkle_root
            # untouched while mutating events passes verification (BC-230).
            current_leaf_ids: list[uuid.UUID] = []
            for s in range(first_seq, last_seq + 1):
                if s in event_ids_by_global_seq:
                    current_leaf_ids.append(event_ids_by_global_seq[s])
            if stored_root is not None and current_leaf_ids:
                recomputed = compute_merkle_root(current_leaf_ids)
                if not _hmac.compare_digest(recomputed, stored_root):
                    total_warnings += 1
                    log.warning(
                        "replay.merkle_root_mismatch",
                        first_seq=first_seq,
                        last_seq=last_seq,
                        recomputed=recomputed.hex(),
                        stored=stored_root.hex(),
                    )

            # Token-integrity check: TSA actually signed the stored root.
            if tsa_token and stored_root:
                if not verify_tsa_token(tsa_token, stored_root, _verify_cfg):
                    total_warnings += 1
                    log.warning(
                        "replay.invalid_tsa_token",
                        first_seq=first_seq,
                        last_seq=last_seq,
                    )
            else:
                total_warnings += 1
                log.warning(
                    "replay.missing_tsa_token",
                    first_seq=first_seq,
                    last_seq=last_seq,
                )
        uncovered = []
        for evt in all_events:
            seq = evt["global_seq"]
            if seq not in covered:
                uncovered.append(seq)
        if uncovered:
            total_warnings += len(uncovered)
            log.warning(
                "replay.uncovered_events",
                count=len(uncovered),
                sample=uncovered[:10],
            )

    return ReplayReport(
        table_name=replay_table,
        replayed_ok=ok_count,
        replayed_drift=drift_count,
        halted=halted_count,
        warnings=total_warnings,
    )


def _parse_not_before(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value)


def _replay_work_item(
    conn: psycopg.Connection,
    wi_id,
    events: list[dict],
    key_set: KeySet,
    continue_on_revoked: bool = False,
) -> tuple[dict, int]:
    state = None
    custom_fields: dict = {}
    needs_review = False
    not_before: datetime | None = None
    last_seq = 0
    attempt_number = 0
    claimed_by: str | None = None
    claim_expires_at: datetime | None = None
    claim_coalesce_threshold: float = 0.0
    warnings = 0

    prev_evt: dict | None = None
    for evt in events:
        transition = evt["transition"]
        last_seq = evt["event_seq"]

        ok, err = _verify_hash_chain(evt, prev_evt)
        if not ok:
            log.warning(
                "replay.hash_chain_broken",
                work_item_id=str(wi_id),
                event_id=str(evt["event_id"]),
                event_seq=evt["event_seq"],
                detail=err,
            )
            warnings += 1

        key_entry = None
        try:
            key_entry = key_set.verify_key_status(
                evt["key_id"],
                event_timestamp=(
                    evt["timestamp"].isoformat()
                    if evt.get("timestamp")
                    else None
                ),
            )
        except SubstrateError as e:
            if e.code == ErrorCode.REVOKED_KEY_ID and continue_on_revoked:
                key_entry = key_set.get_key(evt["key_id"])
                warnings += 1
                log.warning(
                    "replay.revoked_key_signature_verified",
                    work_item_id=str(wi_id),
                    event_id=str(evt["event_id"]),
                    event_seq=evt["event_seq"],
                    key_id=evt["key_id"],
                )
            elif e.code == ErrorCode.UNKNOWN_KEY_ID and continue_on_revoked:
                warnings += 1
                log.warning(
                    "replay.unknown_key_skipped",
                    work_item_id=str(wi_id),
                    event_id=str(evt["event_id"]),
                    event_seq=evt["event_seq"],
                    key_id=evt["key_id"],
                )
            else:
                raise

        if key_entry is not None:
            scheme = get_scheme(evt.get("scheme_id", "hmac-sha256"))
            verify_key = key_entry.secret
            if scheme.scheme_id == "ed25519" and key_entry.public_key:
                verify_key = key_entry.public_key
            if not verify_event(
                event_id=evt["event_id"],
                work_item_id=evt["work_item_id"],
                actor_id=evt["actor_id"],
                key_id=evt["key_id"],
                event_seq=evt["event_seq"],
                workflow_name=evt["workflow_name"],
                workflow_version=evt["workflow_version"],
                timestamp=evt["timestamp"],
                transition=evt["transition"],
                payload=evt["payload"],
                signature=bytes(evt["signature"]),
                canonical_hash=bytes(evt["payload_canonical_hash"]),
                key=verify_key,
                stored_envelope=(
                    bytes(evt["canonical_envelope"]) if evt["canonical_envelope"] else None
                ),
                on_behalf_of=evt["on_behalf_of"],
                scheme=scheme,
            ):
                raise _ReplayHaltError(
                    f"Signature verification failed for event {evt['event_id']} "
                    f"at seq {evt['event_seq']}"
                )

        if transition == "created":
            payload = evt["payload"] or {}
            state = payload.get("initial_state")
            custom_fields = payload.get("custom_fields", {})
            not_before = _parse_not_before(payload.get("not_before"))
        elif transition in (
            "link_created",
            "link_removed",
            "claim_acquired",
            "claim_stolen",
            "claim_released",
            "claim_expired",
            "claim_heartbeat",
            "hook_dead_lettered",
        ):
            if transition in ("claim_acquired", "claim_stolen"):
                attempt_number += 1
            if transition == "claim_acquired":
                payload = evt["payload"] or {}
                claimed_by = payload.get("actor_id")
                expires_str = payload.get("expires_at")
                if expires_str:
                    claim_expires_at = datetime.fromisoformat(expires_str)
            elif transition == "claim_stolen":
                payload = evt["payload"] or {}
                claimed_by = payload.get("new_actor_id")
                expires_str = payload.get("expires_at")
                if expires_str:
                    claim_expires_at = datetime.fromisoformat(expires_str)
            elif transition == "claim_heartbeat":
                payload = evt["payload"] or {}
                expires_str = payload.get("expires_at")
                if expires_str:
                    claim_expires_at = datetime.fromisoformat(expires_str)
                claim_coalesce_threshold = payload.get("coalesce_threshold") or 0.0
            elif transition in ("claim_released", "claim_expired"):
                claimed_by = None
                claim_expires_at = None
                claim_coalesce_threshold = 0.0
        elif transition == "escalated":
            needs_review = True
        elif transition == "not_before_set":
            payload = evt["payload"] or {}
            not_before = _parse_not_before(payload.get("not_before"))
        else:
            wf_row = conn.execute(
                SQL(
                    "SELECT definition FROM workflow_registry "
                    "WHERE workflow_name = %s AND version = %s"
                ),
                [evt["workflow_name"], evt["workflow_version"]],
            ).fetchone()
            if wf_row is None:
                raise _ReplayHaltError(
                    f"Missing workflow {evt['workflow_name']!r} v{evt['workflow_version']}"
                )

            defn = wf_row["definition"]
            found = False
            for t in defn.get("transitions", []):
                if t["name"] == transition and t["from_state"] == state:
                    state = t["to_state"]
                    found = True
                    break
            if not found:
                name_matches = any(
                    t["name"] == transition for t in defn.get("transitions", [])
                )
                if name_matches:
                    raise _ReplayHaltError(
                        f"Transition {transition!r} exists but not valid from state {state!r}"
                    )

            if found:
                payload = evt["payload"] or {}
                if payload.get("custom_fields_update"):
                    custom_fields = {**custom_fields, **payload["custom_fields_update"]}
                claimed_by = None
                claim_expires_at = None

        prev_evt = evt

    return {
        "current_state": state,
        "custom_fields": custom_fields,
        "needs_review": needs_review,
        "not_before": not_before,
        "last_event_seq": last_seq,
        "attempt_number": attempt_number,
        "claimed_by": claimed_by,
        "claim_expires_at": claim_expires_at,
        "claim_coalesce_threshold": claim_coalesce_threshold,
    }, warnings


def _states_match(replayed: dict, live: dict) -> bool:
    if replayed["current_state"] != live["current_state"]:
        return False
    if replayed["last_event_seq"] != live["last_event_seq"]:
        return False
    if replayed["custom_fields"] != live["custom_fields"]:
        return False
    if replayed["needs_review"] != live["needs_review"]:
        return False
    if not _ts_equal(replayed["not_before"], live["not_before"]):
        return False
    if replayed["attempt_number"] != live["attempt_number"]:
        return False
    if replayed["claimed_by"] != live["claimed_by"]:
        return False
    threshold = replayed.get("claim_coalesce_threshold", 0.0)
    if not _ts_equal_within(
        replayed["claim_expires_at"], live["claim_expires_at"], threshold,
    ):
        return False
    return True


def _diff_fields(replayed: dict, live: dict) -> list[str]:
    diffs: list[str] = []
    if replayed["current_state"] != live["current_state"]:
        diffs.append("current_state")
    if replayed["last_event_seq"] != live["last_event_seq"]:
        diffs.append("last_event_seq")
    if replayed["custom_fields"] != live["custom_fields"]:
        diffs.append("custom_fields")
    if replayed["needs_review"] != live["needs_review"]:
        diffs.append("needs_review")
    if not _ts_equal(replayed["not_before"], live["not_before"]):
        diffs.append("not_before")
    if replayed["attempt_number"] != live["attempt_number"]:
        diffs.append("attempt_number")
    if replayed["claimed_by"] != live["claimed_by"]:
        diffs.append("claimed_by")
    threshold = replayed.get("claim_coalesce_threshold", 0.0)
    if not _ts_equal_within(
        replayed["claim_expires_at"], live["claim_expires_at"], threshold,
    ):
        diffs.append("claim_expires_at")
    return diffs
