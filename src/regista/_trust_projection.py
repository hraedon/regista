"""Rebuild ``principal_keys`` from signed events alone (§5.9 rule 4, §9 criterion 12).

``regista trust rebuild-projection --project <p> [--dry-run]``, plus the
``trust:projection_consistent:<project>`` doctor check (§5.9 rule 3).

Three rules govern what a rebuild may touch, and they are the whole design:

1. **v6 rows only.** The rebuild replays the project's stored, signed
   ``principal_key_enrolled`` / ``principal_key_rotated`` / ``principal_key_revoked``
   events and writes exactly the rows they imply.
2. **``legacy_unsourced`` rows are left alone.** There are no signed lifecycle events
   for the HMAC epoch (overlay change 3), so a rebuild cannot reconstruct them. *"A
   rebuild that empties them is a defect, and a rebuild that invents them is worse."*
3. **Divergence is a failure, not a warning**, in production posture.

Where the events come from
--------------------------

The ordinary production v6 append path does not exist yet — that is P1.7. This module
therefore reads **stored** events out of the project's ``events`` (and
``events_archive``) tables and never writes one. It is a pure consumer: give it a
store, it tells you what the projection should be.

Ordering is by ``event_seq`` within the entity, then ``global_seq`` — the stored
materialisation of append order. §5.10's hash-linked chain traversal is the
*verifier's* ordering rule and lands with the v6 verifier (P1.7-adjacent, §9 criteria
14/15); a rebuild reading its own store is entitled to that store's recorded order,
and :func:`rebuild_projection` reports the ordering basis it used so a caller can
tell the difference.
"""

from __future__ import annotations

import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._principal_keys import (
    LEGACY_UNSOURCED,
    PROJECTION_VERSION,
    _apply_enrollment_projection,
    _apply_revocation_projection,
    _apply_rotation_projection,
)
from ._trust_log import (
    PRINCIPAL_KEY_ENROLLED,
    PRINCIPAL_KEY_REVOKED,
    PRINCIPAL_KEY_ROTATED,
    PROJECTION_DRIVING_TRANSITIONS,
    parse_principal_key_enrolled,
    parse_principal_key_revoked,
    parse_principal_key_rotated,
)

#: Columns that make up a row's comparable identity. ``registered_by`` is included:
#: it is part of the row a rebuild must reproduce, and a rebuild that quietly
#: rewrote it would be diffing against itself.
_COMPARED_COLUMNS: tuple[str, ...] = (
    "principal_id",
    "key_id",
    "scheme",
    "public_key",
    "fingerprint",
    "status",
    "valid_from",
    "valid_to",
    "registered_by",
    "registered_at",
    "revoked_at",
    "revoked_reason",
    "trust_domain_id",
    "source_event_hash",
    "acceptance_event_hash",
    "projection_version",
)

_TEMP_TABLE = "_regista_principal_keys_rebuild"


@dataclass(frozen=True)
class RowDifference:
    """One divergence between the live projection and the rebuilt one."""

    principal_id: str
    key_id: str
    kind: str  # "only_live" | "only_rebuilt" | "field_mismatch"
    fields: tuple[str, ...] = ()
    live: Mapping[str, Any] | None = None
    rebuilt: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "kind": self.kind,
            "fields": list(self.fields),
        }


@dataclass(frozen=True)
class RebuildReport:
    """What a rebuild did, or would do under ``--dry-run``."""

    project: str
    dry_run: bool
    events_replayed: int
    events_by_transition: Mapping[str, int]
    rows_rebuilt: int
    legacy_unsourced_preserved: int
    ordering_basis: str
    differences: tuple[RowDifference, ...] = ()
    applied: bool = False
    skipped_events: tuple[Mapping[str, Any], ...] = field(default=())

    @property
    def consistent(self) -> bool:
        return not self.differences

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "dry_run": self.dry_run,
            "applied": self.applied,
            "consistent": self.consistent,
            "events_replayed": self.events_replayed,
            "events_by_transition": dict(self.events_by_transition),
            "rows_rebuilt": self.rows_rebuilt,
            "legacy_unsourced_preserved": self.legacy_unsourced_preserved,
            "ordering_basis": self.ordering_basis,
            "differences": [d.to_dict() for d in self.differences],
            "skipped_events": [dict(s) for s in self.skipped_events],
        }


# ---------------------------------------------------------------------------
# Reading stored trust-log lifecycle events
# ---------------------------------------------------------------------------


def _projection_columns_present(conn: DictConn) -> bool:
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = 'principal_keys' "
        "AND column_name = 'source_event_hash'"
    ).fetchone()
    return bool(row and int(row["n"]) == 1)


def _require_projection_schema(conn: DictConn, project: str) -> None:
    if not _projection_columns_present(conn):
        raise RegistaError(
            ErrorCode.MIGRATION_REQUIRED,
            f"project {project!r} has no principal_keys.source_event_hash column: "
            "migration 046 has not been applied, so there is no provenance to rebuild "
            "against. Run migrations first.",
            {"reason": "projection_columns_absent", "project": project},
        )


def _event_hash_text(row: Mapping[str, Any]) -> str | None:
    """``"sha256:" + hex`` of the v6 event hash, or ``None`` for a legacy row.

    Uses the same construction the rest of the tree uses for a v6 event hash
    (``_signing.compute_v6_event_hash``), so a rebuild's ``source_event_hash``
    matches what a writer stamped.
    """
    envelope = row.get("canonical_envelope")
    signature = row.get("signature")
    if envelope is None or signature is None:
        return None
    from ._signing import compute_v6_event_hash

    return "sha256:" + compute_v6_event_hash(bytes(envelope), bytes(signature)).hex()


def read_lifecycle_events(conn: DictConn) -> list[dict[str, Any]]:
    """Stored ``principal_key_*`` events, in recorded append order.

    Reads live events and archived events, so archiving a segment does not silently
    shrink the projection (the archive is part of the log, not a deletion).
    """
    transitions = sorted(PROJECTION_DRIVING_TRANSITIONS)
    rows: list[dict[str, Any]] = []
    for relation in ("events", "events_archive"):
        exists = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s) AS present",
            [relation],
        ).fetchone()
        if not exists or not exists["present"]:
            continue
        fetched = conn.execute(
            f"SELECT event_id, entity_kind, entity_id, event_seq, global_seq, "
            f"transition, payload, timestamp, canonical_envelope, signature, "
            f"scheme_id, actor_id FROM {relation} "
            "WHERE transition = ANY(%s) ORDER BY global_seq",
            [transitions],
        ).fetchall()
        rows.extend(dict(r) for r in fetched)
    rows.sort(key=lambda r: (int(r["global_seq"]) if r["global_seq"] is not None else 0,
                             int(r["event_seq"]) if r["event_seq"] is not None else 0))
    return rows


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def _as_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    raise RegistaError(
        ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
        f"expected a timestamp, got {type(value).__name__}",
        {"reason": "not_a_timestamp"},
    )


def _replay_into(
    conn: DictConn,
    events: Sequence[Mapping[str, Any]],
    *,
    table: str,
) -> tuple[int, dict[str, int], list[dict[str, Any]]]:
    """Apply ``events`` to ``table`` via the private appliers, in order.

    Deliberately reuses the **same** appliers the write path uses. A rebuild with its
    own INSERT statements would be a second, drifting definition of the projection —
    and then "the rebuild matches" would only mean the two copies of the logic agree.
    """
    by_transition: dict[str, int] = {}
    skipped: list[dict[str, Any]] = []
    replayed = 0
    for row in events:
        transition = str(row["transition"])
        payload = row["payload"]
        source_event_hash = _event_hash_text(row)
        if source_event_hash is None:
            # A lifecycle transition with no v6 envelope is a legacy-epoch event; it
            # is not lifecycle evidence and cannot source a v6 row (overlay change 3).
            skipped.append(
                {
                    "event_id": str(row.get("event_id")),
                    "transition": transition,
                    "reason": "no_v6_envelope",
                }
            )
            continue
        if not isinstance(payload, Mapping):
            skipped.append(
                {
                    "event_id": str(row.get("event_id")),
                    "transition": transition,
                    "reason": "payload_not_an_object",
                }
            )
            continue
        occurred_at = _as_datetime(row["timestamp"])
        if transition == PRINCIPAL_KEY_ENROLLED:
            parsed = parse_principal_key_enrolled(payload)
            _apply_enrollment_projection(
                conn,
                parsed.principal_id,
                parsed.key.public_key,
                parsed.key.scheme_id,
                source_event_hash=source_event_hash,
                valid_from=parsed.not_before,
                valid_to=parsed.not_after,
                registered_at=occurred_at,
                key_id=parsed.key.key_id,
                registered_by=parsed.authorized_by.principal_id,
                trust_domain_id=parsed.trust_domain_id,
                _table=table,
            )
        elif transition == PRINCIPAL_KEY_ROTATED:
            rotated = parse_principal_key_rotated(payload)
            _apply_rotation_projection(
                conn,
                rotated.principal_id,
                rotated.key.public_key,
                rotated.key.scheme_id,
                source_event_hash=source_event_hash,
                valid_from=rotated.not_before,
                valid_to=rotated.not_after,
                registered_at=occurred_at,
                key_id=rotated.key.key_id,
                registered_by=rotated.authorized_by.principal_id,
                trust_domain_id=rotated.trust_domain_id,
                _table=table,
            )
        elif transition == PRINCIPAL_KEY_REVOKED:
            revoked = parse_principal_key_revoked(payload)
            _apply_revocation_projection(
                conn,
                revoked.principal_id,
                revoked.key_id,
                source_event_hash=source_event_hash,
                revoked_at=revoked.revoked_at,
                reason=revoked.reason,
                _table=table,
            )
        else:  # pragma: no cover - PROJECTION_DRIVING_TRANSITIONS is closed
            raise AssertionError(f"unhandled transition {transition!r}")
        by_transition[transition] = by_transition.get(transition, 0) + 1
        replayed += 1
    return replayed, by_transition, skipped


# ---------------------------------------------------------------------------
# Diffing
# ---------------------------------------------------------------------------


def _normalize(value: Any) -> Any:
    if isinstance(value, memoryview | bytearray):
        return bytes(value)
    if isinstance(value, _uuid.UUID):
        return str(value)
    return value


def _row_key(row: Mapping[str, Any]) -> tuple[str, str]:
    return (str(row["principal_id"]), str(row["key_id"]))


def _fetch_rows(conn: DictConn, table: str, *, v6_only: bool) -> dict[
    tuple[str, str], dict[str, Any]
]:
    columns = ", ".join(_COMPARED_COLUMNS)
    where = "WHERE source_event_hash IS NOT NULL" if v6_only else ""
    rows = conn.execute(
        f"SELECT {columns} FROM {table} {where}"
    ).fetchall()
    return {
        _row_key(r): {k: _normalize(dict(r)[k]) for k in _COMPARED_COLUMNS} for r in rows
    }


def _diff(
    live: Mapping[tuple[str, str], Mapping[str, Any]],
    rebuilt: Mapping[tuple[str, str], Mapping[str, Any]],
) -> tuple[RowDifference, ...]:
    out: list[RowDifference] = []
    for key in sorted(set(live) - set(rebuilt)):
        out.append(
            RowDifference(
                principal_id=key[0], key_id=key[1], kind="only_live", live=live[key]
            )
        )
    for key in sorted(set(rebuilt) - set(live)):
        out.append(
            RowDifference(
                principal_id=key[0],
                key_id=key[1],
                kind="only_rebuilt",
                rebuilt=rebuilt[key],
            )
        )
    for key in sorted(set(live) & set(rebuilt)):
        mismatched = tuple(
            column
            for column in _COMPARED_COLUMNS
            if live[key][column] != rebuilt[key][column]
        )
        if mismatched:
            out.append(
                RowDifference(
                    principal_id=key[0],
                    key_id=key[1],
                    kind="field_mismatch",
                    fields=mismatched,
                    live=live[key],
                    rebuilt=rebuilt[key],
                )
            )
    return tuple(out)


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def rebuild_projection(
    mgr: ConnectionManager,
    *,
    project: str,
    dry_run: bool = False,
) -> RebuildReport:
    """Rebuild the v6 rows of ``principal_keys`` from signed events alone.

    With ``dry_run=True`` nothing is written: the rebuild happens in a temp table,
    the result is diffed against the live projection, and the report says what would
    change. Without it, the same diff is computed and then the v6 rows are replaced
    by the rebuilt ones **in one transaction**.

    ``legacy_unsourced`` rows are never read, never written, never deleted — only
    counted, so the report can state how many survived.
    """
    with mgr.transaction() as conn:
        _require_projection_schema(conn, project)
        events = read_lifecycle_events(conn)

        legacy_count_row = conn.execute(
            "SELECT COUNT(*) AS n FROM principal_keys WHERE source_event_hash IS NULL"
        ).fetchone()
        legacy_before = int(legacy_count_row["n"]) if legacy_count_row else 0

        conn.execute(f"DROP TABLE IF EXISTS {_TEMP_TABLE}")
        conn.execute(
            f"CREATE TEMP TABLE {_TEMP_TABLE} "
            "(LIKE principal_keys INCLUDING DEFAULTS INCLUDING CONSTRAINTS)"
        )
        replayed, by_transition, skipped = _replay_into(conn, events, table=_TEMP_TABLE)

        live = _fetch_rows(conn, "principal_keys", v6_only=True)
        rebuilt = _fetch_rows(conn, _TEMP_TABLE, v6_only=True)
        differences = _diff(live, rebuilt)

        applied = False
        if not dry_run:
            # Replace only the v6 rows. The legacy rows are not in the DELETE's scope
            # at all, which is the structural form of "leave legacy_unsourced alone".
            conn.execute("DELETE FROM principal_keys WHERE source_event_hash IS NOT NULL")
            columns = ", ".join(_COMPARED_COLUMNS)
            conn.execute(
                f"INSERT INTO principal_keys ({columns}) "
                f"SELECT {columns} FROM {_TEMP_TABLE} WHERE source_event_hash IS NOT NULL"
            )
            applied = True

        legacy_after_row = conn.execute(
            "SELECT COUNT(*) AS n FROM principal_keys WHERE source_event_hash IS NULL"
        ).fetchone()
        legacy_after = int(legacy_after_row["n"]) if legacy_after_row else 0
        # The preservation invariant, asserted rather than assumed: a rebuild that
        # dropped a legacy row would otherwise look like a success.
        if legacy_after != legacy_before:
            raise RegistaError(
                ErrorCode.PRINCIPAL_KEYS_PROJECTION_DIVERGED,
                f"rebuild changed the legacy_unsourced row count for {project!r}: "
                f"{legacy_before} -> {legacy_after}. A rebuild that empties them is a "
                "defect and one that invents them is worse (TRUST-DOMAIN.md §5.9).",
                {
                    "reason": "legacy_unsourced_row_count_changed",
                    "project": project,
                    "before": legacy_before,
                    "after": legacy_after,
                },
            )

        conn.execute(f"DROP TABLE IF EXISTS {_TEMP_TABLE}")

        return RebuildReport(
            project=project,
            dry_run=dry_run,
            events_replayed=replayed,
            events_by_transition=by_transition,
            rows_rebuilt=len(rebuilt),
            legacy_unsourced_preserved=legacy_after,
            ordering_basis="stored_append_order(global_seq,event_seq)",
            differences=differences,
            applied=applied,
            skipped_events=tuple(skipped),
        )


def check_projection_consistent(
    mgr: ConnectionManager, *, project: str
) -> RebuildReport:
    """§5.9 rule 3: rebuild into a temp table and diff. Never writes.

    Returns the report; the caller decides the posture. ``regista doctor`` treats any
    divergence as **fail**, not warn.
    """
    return rebuild_projection(mgr, project=project, dry_run=True)


def projection_summary(mgr: ConnectionManager) -> dict[str, int]:
    """Row counts by provenance, for reporting surfaces."""
    with mgr.transaction() as conn:
        if not _projection_columns_present(conn):
            row = conn.execute("SELECT COUNT(*) AS n FROM principal_keys").fetchone()
            return {LEGACY_UNSOURCED: int(row["n"]) if row else 0, "v6_sourced": 0}
        rows = conn.execute(
            "SELECT source_event_hash IS NULL AS is_legacy, COUNT(*) AS n "
            "FROM principal_keys GROUP BY 1"
        ).fetchall()
    out = {LEGACY_UNSOURCED: 0, "v6_sourced": 0}
    for row in rows:
        out[LEGACY_UNSOURCED if row["is_legacy"] else "v6_sourced"] = int(row["n"])
    return out


__all__: Sequence[str] = [
    "PROJECTION_VERSION",
    "RebuildReport",
    "RowDifference",
    "check_projection_consistent",
    "projection_summary",
    "read_lifecycle_events",
    "rebuild_projection",
]
