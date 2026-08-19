"""Rebuild ``principal_keys`` from signed events alone (§5.9 rule 4, §9 criterion 12).

``regista trust rebuild-projection --project <p> [--dry-run]``, plus the
``trust:projection_consistent:<project>`` doctor check (§5.9 rule 3).

Three rules govern what a rebuild may touch, and they are the whole design:

1. **v6 rows only.** The rebuild replays the ordered, authority-verified trust-log
   ``principal_key_enrolled`` / ``principal_key_rotated`` / ``principal_key_revoked``
   events and writes exactly the rows they imply. A separate coordinator can import
   that verified sequence into another project schema.
2. **``legacy_unsourced`` rows are left alone.** There are no signed lifecycle events
   for the HMAC epoch (overlay change 3), so a rebuild cannot reconstruct them. *"A
   rebuild that empties them is a defect, and a rebuild that invents them is worse."*
3. **Divergence is a failure, not a warning**, in production posture.

Where the events come from
--------------------------

The default :func:`rebuild_projection` entry point verifies the trust-log chain in the
same schema before staging any projection mutation. For the estate topology, use
:func:`rebuild_projection_from_trust_log` to verify the trust-log schema and apply its
ordered result to a separate project schema, binding any project-chain acceptance by
its exact event hash. The projection is never used as verification evidence.
"""

from __future__ import annotations

import uuid as _uuid
import warnings
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, NoReturn

from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._principal_keys import (
    LEGACY_UNSOURCED,
    PROJECTION_VERSION,
)
from ._signing import compute_v6_event_hash
from ._signing_scheme import is_v6_scheme
from ._trust_log import (
    PRINCIPAL_KEY_ENROLLED,
    PRINCIPAL_KEY_REVOKED,
    PRINCIPAL_KEY_ROTATED,
    TRUST_DOMAIN_ESTABLISHED,
    TRUST_LOG_TRANSITIONS,
)
from ._v6_referents import (
    MappingReferents,
    MaterialCompleteness,
    referent_from_bytes,
    walk_project_chain,
)
from ._v6_writer import validate_key_acceptance_payload
from ._verification import (
    EventRow,
    StaticKeyResolver,
    TrustedKeySource,
    verify_event_strict,
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
    kind: str  # "only_live" | "only_rebuilt" | "field_mismatch" | legacy collision
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


@dataclass(frozen=True)
class VerifiedAcceptance:
    """Caller-supplied, cryptographically verified project acceptance evidence.

    The event hash alone is not evidence: a coordinator must obtain this record from
    :func:`verify_project_acceptance`, which checks the signed project row and its
    predecessor chain. Rebuild validates the record again before inserting it into a
    projection, so fabricated hashes cannot enter through the cross-schema seam.
    """

    event_hash: str
    principal_id: str
    key_id: str
    project_instance_id: str
    trust_domain_id: str
    signer_public_key: bytes


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
    """``"sha256:" + hex`` of the event hash, or ``None`` when it cannot be computed.

    **Branches on ``scheme_id``**, mirroring
    ``principal_lifecycle._lifecycle_event_hash`` exactly. The two must agree: the
    write path stamps ``source_event_hash`` and the rebuild recomputes it, so a
    construction mismatch would make every affected row read as divergence and — on
    an applied rebuild — be replaced by a row carrying a different provenance hash.
    That is the "invents rows" direction §5.9 warns about.

    An **asymmetric-schemed** event uses the domain-separated v6 construction;
    anything else (an HMAC-schemed lifecycle event in a pre-cutover store) uses the
    legacy ``sha256(canonical_envelope || signature)`` head-hash form. Labelling a
    legacy event with a v6-domain hash would be a false claim about which epoch
    produced it.

    NB3 (P2.2 review): the test is scheme-class membership, not the ``"ed25519"``
    literal, so the next asymmetric scheme added to the registry is classified v6
    automatically instead of being silently mislabelled legacy. The predicate lives
    in :mod:`regista._signing_scheme`, beside the registry, and the write path
    imports the same one.
    """
    envelope = row.get("canonical_envelope")
    signature = row.get("signature")
    if envelope is None or signature is None:
        return None
    if is_v6_scheme(row.get("scheme_id")):
        from ._signing import compute_v6_event_hash

        return "sha256:" + compute_v6_event_hash(bytes(envelope), bytes(signature)).hex()
    import hashlib as _hashlib

    return "sha256:" + _hashlib.sha256(bytes(envelope) + bytes(signature)).hexdigest()


def read_lifecycle_events(_conn: DictConn) -> NoReturn:
    """Deprecated refusal for the removed unverified projection read path."""
    warnings.warn(
        "read_lifecycle_events is deprecated; use verified trust-log rebuilds instead",
        DeprecationWarning,
        stacklevel=2,
    )
    raise RegistaError(
        ErrorCode.INVALID_ARGUMENT,
        "unverified lifecycle reads were removed; use rebuild_projection with a pinned "
        "trust genesis document",
        {"reason": "unverified_projection_read_removed"},
    )


def _acceptance_refusal(reason: str, message: str, **detail: Any) -> RegistaError:
    return RegistaError(
        ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED,
        message,
        {"reason": reason, **detail},
    )


def _project_chain_material(conn: DictConn) -> tuple[MappingReferents, str]:
    """Present the complete live/archive project chain and its stored head."""
    events: dict[str, Any] = {}
    for relation in ("events", "events_archive"):
        exists = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s) AS present",
            [relation],
        ).fetchone()
        if not exists or not exists["present"]:
            continue
        rows = conn.execute(
            f"SELECT canonical_envelope, signature FROM {relation} "
            "WHERE canonical_envelope IS NOT NULL AND signature IS NOT NULL"
        ).fetchall()
        for row in rows:
            referent = referent_from_bytes(row["canonical_envelope"], row["signature"])
            if referent is not None:
                events.setdefault(referent.event_hash, referent)

    head_row = conn.execute(
        "SELECT head_hash FROM event_chain_head WHERE id = TRUE"
    ).fetchone()
    if head_row is None or head_row["head_hash"] is None:
        raise _acceptance_refusal(
            "acceptance_project_chain_head_missing",
            "project acceptance verification requires a stored project-chain head",
        )
    head = "sha256:" + bytes(head_row["head_hash"]).hex()
    return (
        MappingReferents(
            events=events,
            material_completeness=MaterialCompleteness.COMPLETE_STORE,
            label="project acceptance coordinator",
        ),
        head,
    )


def _require_acceptance_on_project_head_chain(
    event_hash: str,
    head: str,
    referents: MappingReferents,
) -> None:
    path = tuple(walk_project_chain(head, referents))
    if not path or path[-1].previous_project_event_hash is not None:
        raise _acceptance_refusal(
            "acceptance_project_chain_orphan",
            "the project-chain head cannot be walked back to project genesis",
            event_hash=event_hash,
            head=head,
        )

    path_hashes = {event.event_hash for event in path}
    if event_hash not in path_hashes:
        raise _acceptance_refusal(
            "acceptance_not_on_project_head_chain",
            "project acceptance is not on the single predecessor path from the "
            "project-chain head to project genesis",
            event_hash=event_hash,
            head=head,
        )

    successors: dict[str, list[str]] = {}
    for event in referents.events.values():
        predecessor = event.previous_project_event_hash
        if predecessor is not None:
            successors.setdefault(predecessor, []).append(event.event_hash)
    forks = {
        predecessor: children
        for predecessor, children in successors.items()
        if len(children) > 1
    }
    if forks:
        raise _acceptance_refusal(
            "acceptance_project_chain_fork",
            "the project store contains a predecessor with multiple successors",
            forks=forks,
        )
    orphaned = sorted(set(referents.events) - path_hashes)
    if orphaned:
        raise _acceptance_refusal(
            "acceptance_project_chain_orphan",
            "the project store contains v6 events outside the head-to-genesis path",
            orphaned_event_hashes=orphaned,
        )


def verify_project_acceptance(
    conn: DictConn,
    *,
    event_hash: str,
    public_key: bytes,
) -> VerifiedAcceptance:
    """Verify one project-chain ``principal_key_accepted`` event.

    This is the trust boundary for the cross-schema coordinator. It verifies the
    signed row, row/envelope reconciliation, and the project predecessor chain using
    the supplied public key; callers must still bind the returned acceptance to the
    corresponding trust-log lifecycle event during rebuild.
    """
    if (
        not isinstance(event_hash, str)
        or len(event_hash) != 71
        or not event_hash.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in event_hash[7:])
    ):
        raise _acceptance_refusal(
            "acceptance_event_hash_malformed",
            "project acceptance evidence carries a malformed event hash",
        )
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise _acceptance_refusal(
            "acceptance_public_key_malformed",
            "project acceptance evidence requires a 32-byte Ed25519 public key",
        )

    matching: dict[str, Any] | None = None
    for relation in ("events", "events_archive"):
        exists = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s) AS present",
            [relation],
        ).fetchone()
        if not exists or not exists["present"]:
            continue
        rows = conn.execute(
            f"SELECT * FROM {relation} WHERE transition = %s",
            ["principal_key_accepted"],
        ).fetchall()
        for raw in rows:
            row = dict(raw)
            if not row.get("canonical_envelope") or not row.get("signature"):
                continue
            computed = "sha256:" + compute_v6_event_hash(
                bytes(row["canonical_envelope"]), bytes(row["signature"])
            ).hex()
            if computed == event_hash:
                matching = row
                break
        if matching is not None:
            break
    if matching is None:
        raise _acceptance_refusal(
            "acceptance_event_not_found",
            "project acceptance evidence names no stored signed acceptance event",
            event_hash=event_hash,
        )

    referents, head = _project_chain_material(conn)
    result = verify_event_strict(
        EventRow.from_mapping(matching),
        keys=StaticKeyResolver(
            material=bytes(public_key),
            scheme_id="ed25519",
            source=TrustedKeySource.SUPPLIED_PUBLIC_KEY,
        ),
        referents=referents,
    )
    if not result.ok or not result.signature_valid or not result.row_reconciled:
        raise _acceptance_refusal(
            "acceptance_signature_or_row_invalid",
            "project acceptance evidence does not verify as a fully authenticated "
            "signed reconciled event",
            event_hash=event_hash,
            verification_ok=result.ok,
            signature_valid=result.signature_valid,
            row_reconciled=result.row_reconciled,
            mismatched_fields=[m.field for m in result.mismatched_fields],
            reasons=[str(reason) for reason in result.reasons],
        )
    if result.prev_global_event_hash_ok is not True:
        raise _acceptance_refusal(
            "acceptance_project_chain_invalid",
            "project acceptance evidence does not verify its predecessor chain",
            event_hash=event_hash,
        )
    _require_acceptance_on_project_head_chain(event_hash, head, referents)

    from ._verification import parse_v6_envelope_strict

    envelope = parse_v6_envelope_strict(bytes(matching["canonical_envelope"]))
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        raise _acceptance_refusal(
            "acceptance_payload_not_object",
            "project acceptance event carries no object payload",
            event_hash=event_hash,
        )
    validate_key_acceptance_payload(payload)
    return VerifiedAcceptance(
        event_hash=event_hash,
        principal_id=str(payload["principal_id"]),
        key_id=str(payload["key_id"]),
        project_instance_id=str(payload["project_instance_id"]),
        trust_domain_id=str(payload["trust_domain_id"]),
        signer_public_key=bytes(public_key),
    )


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
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        key = _row_key(r)
        if key in out:
            # Keying by (principal_id, key_id) would otherwise silently collapse a
            # duplicate, and the diff would report agreement between a table with
            # two rows and a rebuild with one.
            raise RegistaError(
                ErrorCode.PRINCIPAL_KEYS_PROJECTION_DIVERGED,
                f"{table} contains more than one row for principal_id={key[0]!r} "
                f"key_id={key[1]!r}; the projection's primary key is not unique, so "
                "no comparison against a rebuild is meaningful",
                {
                    "reason": "duplicate_projection_row",
                    "table": table,
                    "principal_id": key[0],
                    "key_id": key[1],
                },
            )
        out[key] = {k: _normalize(dict(r)[k]) for k in _COMPARED_COLUMNS}
    return out


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


def _stored_trust_log_event_count(conn: DictConn) -> int:
    """Count a stored trust log without requiring a genesis document.

    A project chain may contain legacy lifecycle transitions with the same names. It
    is a trust log only when ``trust_domain_established`` is present; without that
    genesis none of those rows is eligible for verified projection replay.
    """
    total = 0
    genesis = 0
    for relation in ("events", "events_archive"):
        exists = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s) AS present",
            [relation],
        ).fetchone()
        if not exists or not exists["present"]:
            continue
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM {relation} WHERE transition = ANY(%s)",
            [sorted(TRUST_LOG_TRANSITIONS)],
        ).fetchone()
        total += int(row["n"]) if row else 0
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM {relation} WHERE transition = %s",
            [TRUST_DOMAIN_ESTABLISHED],
        ).fetchone()
        genesis += int(row["n"]) if row else 0
    return total if genesis else 0


def _require_genesis_for_nonempty_log(event_count: int) -> RegistaError:
    return RegistaError(
        ErrorCode.TRUST_LOG_PAYLOAD_INVALID,
        "a pinned trust genesis document is required when the trust log contains "
        "stored events",
        {
            "reason": "genesis_document_required",
            "trust_log_events": event_count,
        },
    )


def _verified_trust_log_events(
    conn: DictConn,
    genesis_document: Mapping[str, Any] | None,
) -> Sequence[Any]:
    """Return verified events, allowing only the explicitly empty-log exception."""
    if genesis_document is None:
        event_count = _stored_trust_log_event_count(conn)
        if event_count:
            raise _require_genesis_for_nonempty_log(event_count)
        return ()
    from ._trust_log_writer import verify_trust_log_chain

    return verify_trust_log_chain(conn, genesis_document).verified


def rebuild_projection(
    mgr: ConnectionManager,
    *,
    project: str,
    genesis_document: Mapping[str, Any] | None = None,
    dry_run: bool = False,
    acceptance_by_principal: Mapping[str, VerifiedAcceptance] | None = None,
) -> RebuildReport:
    """Rebuild ``principal_keys`` from wallet sources alone.

    The single verified trust-log walk (``verify_trust_log_chain``) produces the
    ordered, authority-verified lifecycle events; anything unverified raises here,
    **before** any projection mutation. Stage into a temp table, diff, then (unless
    ``dry_run``) replace the tracked rows in one transaction. A failure leaves the
    prior projection untouched.
    """
    with mgr.transaction() as conn:
        _require_projection_schema(conn, project)
        return _rebuild_verified_in_transaction(
            conn,
            project=project,
            verified=_verified_trust_log_events(conn, genesis_document),
            dry_run=dry_run,
            acceptance_by_principal=acceptance_by_principal,
        )


def rebuild_projection_from_trust_log(
    projection_mgr: ConnectionManager,
    trust_log_mgr: ConnectionManager,
    *,
    project: str,
    genesis_document: Mapping[str, Any] | None = None,
    dry_run: bool = False,
    acceptance_by_principal: Mapping[str, VerifiedAcceptance] | None = None,
) -> RebuildReport:
    """Coordinate a verified trust-log replay into a separate project schema."""
    with trust_log_mgr.transaction() as trust_conn:
        verified = _verified_trust_log_events(trust_conn, genesis_document)
    return rebuild_projection_from_verified_chain(
        projection_mgr,
        project=project,
        verified=verified,
        dry_run=dry_run,
        acceptance_by_principal=acceptance_by_principal,
    )


def rebuild_projection_from_verified_chain(
    mgr: ConnectionManager,
    *,
    project: str,
    verified: Sequence[Any],
    dry_run: bool = False,
    acceptance_by_principal: Mapping[str, VerifiedAcceptance] | None = None,
) -> RebuildReport:
    """Apply a chain already verified by an explicit trust-log coordinator."""
    with mgr.transaction() as conn:
        _require_projection_schema(conn, project)
        return _rebuild_verified_in_transaction(
            conn,
            project=project,
            verified=verified,
            dry_run=dry_run,
            acceptance_by_principal=acceptance_by_principal,
        )


def _rebuild_verified_in_transaction(
    conn: DictConn,
    *,
    project: str,
    verified: Sequence[Any],
    dry_run: bool,
    acceptance_by_principal: Mapping[str, VerifiedAcceptance] | None,
) -> RebuildReport:
    for principal_id, evidence in (acceptance_by_principal or {}).items():
        if not isinstance(evidence, VerifiedAcceptance):
            raise _acceptance_refusal(
                "acceptance_evidence_unstructured",
                "acceptance_by_principal must contain VerifiedAcceptance records, not raw hashes",
                principal_id=principal_id,
            )
    live_all = _fetch_rows(conn, "principal_keys", v6_only=False)
    legacy = {
        key: row for key, row in live_all.items() if row["source_event_hash"] is None
    }
    live_v6 = {
        key: row for key, row in live_all.items() if row["source_event_hash"] is not None
    }
    if not verified and live_v6 and not dry_run:
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED,
            "refusing to replace a populated v6 projection without verified lifecycle "
            "evidence",
            {
                "reason": "verified_lifecycle_evidence_missing",
                "project": project,
                "live_v6_rows": len(live_v6),
            },
        )
    legacy_before = len(legacy)

    conn.execute(f"DROP TABLE IF EXISTS {_TEMP_TABLE}")
    conn.execute(
        f"CREATE TEMP TABLE {_TEMP_TABLE} "
        "(LIKE principal_keys INCLUDING DEFAULTS INCLUDING CONSTRAINTS)"
    )
    replayed, by_transition = _apply_verified(
        conn, verified, table=_TEMP_TABLE, acceptances=acceptance_by_principal
    )

    live = live_v6
    rebuilt = _fetch_rows(conn, _TEMP_TABLE, v6_only=True)
    collision_keys = sorted(set(legacy) & set(rebuilt))
    collision_differences = tuple(
        RowDifference(
            principal_id=key[0],
            key_id=key[1],
            kind="legacy_v6_pk_collision",
            fields=("primary_key",),
            live=legacy[key],
            rebuilt=rebuilt[key],
        )
        for key in collision_keys
    )
    differences = _diff(
        {key: row for key, row in live.items() if key not in collision_keys},
        {key: row for key, row in rebuilt.items() if key not in collision_keys},
    ) + collision_differences

    acceptance_evidence_lost = sorted(
        key
        for key in set(live) & set(rebuilt)
        if live[key]["acceptance_event_hash"] is not None
        and rebuilt[key]["acceptance_event_hash"] is None
    )
    if acceptance_evidence_lost and not dry_run:
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED,
            "refusing to discard project-acceptance evidence during projection rebuild",
            {
                "reason": "acceptance_evidence_required",
                "project": project,
                "principals": [
                    {"principal_id": principal_id, "key_id": key_id}
                    for principal_id, key_id in acceptance_evidence_lost
                ],
            },
        )

    if collision_keys and not dry_run:
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEYS_PROJECTION_DIVERGED,
            "the rebuilt v6 projection collides with legacy_unsourced primary-key "
            "rows; refusing to delete or overwrite the legacy rows",
            {
                "reason": "legacy_v6_primary_key_collision",
                "project": project,
                "collisions": [
                    {"principal_id": principal_id, "key_id": key_id}
                    for principal_id, key_id in collision_keys
                ],
            },
        )

    applied = False
    if not dry_run:
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
    if legacy_after != legacy_before:
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEYS_PROJECTION_DIVERGED,
            f"rebuild changed the legacy_unsourced row count for {project!r}: "
            f"{legacy_before} -> {legacy_after}",
            {"reason": "legacy_unsourced_row_count_changed", "project": project},
        )

    conn.execute(f"DROP TABLE IF EXISTS {_TEMP_TABLE}")
    return RebuildReport(
        project=project,
        dry_run=dry_run,
        events_replayed=replayed,
        events_by_transition=by_transition,
        rows_rebuilt=len(rebuilt),
        legacy_unsourced_preserved=legacy_after,
        ordering_basis="verified_predecessor_chain",
        differences=differences,
        applied=applied,
        skipped_events=(),
    )


def _apply_verified(
    conn: DictConn,
    verified: Sequence[Any],
    *,
    table: str,
    acceptances: Mapping[str, VerifiedAcceptance] | None,
) -> tuple[int, dict[str, int]]:
    from ._principal_keys import (
        _apply_enrollment_projection,
        _apply_revocation_projection,
        _apply_rotation_projection,
    )
    from ._trust_log import (
        parse_principal_key_enrolled,
        parse_principal_key_revoked,
        parse_principal_key_rotated,
    )

    if acceptances is None:
        acceptances = {}
    by_transition: dict[str, int] = {}
    replayed = 0
    for record in verified:
        payload = record.payload
        occurred_at = record.occurred_at
        if record.transition == PRINCIPAL_KEY_ENROLLED:
            parsed = parse_principal_key_enrolled(payload)
            acceptance_hash = _acceptance_hash_for_record(
                conn,
                acceptances,
                parsed.principal_id,
                parsed,
                record.event_hash,
            )
            _apply_enrollment_projection(
                conn,
                parsed.principal_id,
                parsed.key.public_key,
                parsed.key.scheme_id,
                source_event_hash=record.event_hash,
                valid_from=parsed.not_before,
                valid_to=parsed.not_after,
                registered_at=occurred_at,
                key_id=parsed.key.key_id,
                registered_by=parsed.authorized_by.principal_id,
                trust_domain_id=_trust_domain_id_text(record),
                acceptance_event_hash=acceptance_hash,
                _table=table,
            )
        elif record.transition == PRINCIPAL_KEY_ROTATED:
            rotated = parse_principal_key_rotated(payload)
            _apply_rotation_projection(
                conn,
                rotated.principal_id,
                rotated.key.public_key,
                rotated.key.scheme_id,
                source_event_hash=record.event_hash,
                valid_from=rotated.not_before,
                valid_to=rotated.not_after,
                registered_at=occurred_at,
                key_id=rotated.key.key_id,
                registered_by=rotated.authorized_by.principal_id,
                trust_domain_id=_trust_domain_id_text(record),
                _table=table,
            )
        elif record.transition == PRINCIPAL_KEY_REVOKED:
            revoked = parse_principal_key_revoked(payload)
            _apply_revocation_projection(
                conn,
                revoked.principal_id,
                revoked.key_id,
                source_event_hash=record.event_hash,
                revoked_at=revoked.revoked_at,
                reason=revoked.reason,
                _table=table,
            )
        else:
            raise AssertionError(f"unhandled verified lifecycle transition {record.transition!r}")
        by_transition[record.transition] = by_transition.get(record.transition, 0) + 1
        replayed += 1
    return replayed, by_transition


def _acceptance_hash_for_record(
    conn: DictConn,
    acceptances: Mapping[str, VerifiedAcceptance] | None,
    principal_id: str,
    parsed: Any,
    trust_event_hash: str,
) -> str | None:
    if acceptances is None:
        return None
    evidence = acceptances.get(principal_id)
    if evidence is None:
        return None
    if not isinstance(evidence, VerifiedAcceptance):
        raise _acceptance_refusal(
            "acceptance_evidence_unstructured",
            "acceptance_by_principal must contain VerifiedAcceptance records, not raw hashes",
            principal_id=principal_id,
        )
    verified = verify_project_acceptance(
        conn,
        event_hash=evidence.event_hash,
        public_key=evidence.signer_public_key,
    )
    if (
        verified.principal_id != principal_id
        or verified.key_id != parsed.key.key_id
        or verified.project_instance_id != _project_instance_id(conn)
        or verified.trust_domain_id != parsed.trust_domain_id
    ):
        raise _acceptance_refusal(
            "acceptance_evidence_binding_mismatch",
            "project acceptance evidence does not bind to the trust-log enrollment",
            principal_id=principal_id,
            acceptance_event_hash=verified.event_hash,
            trust_event_hash=trust_event_hash,
        )
    acceptance_payload = _acceptance_payload_by_hash(conn, verified.event_hash)
    if acceptance_payload.get("trust_event_hash") != trust_event_hash:
        raise _acceptance_refusal(
            "acceptance_trust_event_mismatch",
            "project acceptance does not name the verified trust-log enrollment",
            principal_id=principal_id,
            acceptance_event_hash=verified.event_hash,
            trust_event_hash=trust_event_hash,
        )
    return verified.event_hash


def _project_instance_id(conn: DictConn) -> str:
    row = conn.execute(
        "SELECT project_instance_id FROM project_identity WHERE id = TRUE"
    ).fetchone()
    if row is None:
        raise _acceptance_refusal(
            "project_identity_missing",
            "project acceptance verification requires the project's v6 identity",
        )
    return str(row["project_instance_id"])


def _acceptance_payload_by_hash(conn: DictConn, event_hash: str) -> Mapping[str, Any]:
    from ._verification import parse_v6_envelope_strict

    for relation in ("events", "events_archive"):
        exists = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s) AS present",
            [relation],
        ).fetchone()
        if not exists or not exists["present"]:
            continue
        rows = conn.execute(
            f"SELECT canonical_envelope, signature FROM {relation} WHERE transition = %s",
            ["principal_key_accepted"],
        ).fetchall()
        for row in rows:
            if not row["canonical_envelope"] or not row["signature"]:
                continue
            candidate = "sha256:" + compute_v6_event_hash(
                bytes(row["canonical_envelope"]), bytes(row["signature"])
            ).hex()
            if candidate == event_hash:
                envelope = parse_v6_envelope_strict(bytes(row["canonical_envelope"]))
                payload = envelope.get("payload")
                if isinstance(payload, Mapping):
                    return payload
    raise _acceptance_refusal(
        "acceptance_event_not_found",
        "verified project acceptance disappeared during projection",
        event_hash=event_hash,
    )


def _trust_domain_id_text(record: Any) -> str:
    return str(record.payload.get("trust_domain_id") or "")


def check_projection_consistent(
    mgr: ConnectionManager,
    *,
    project: str,
    genesis_document: Mapping[str, Any] | None = None,
) -> RebuildReport:
    """Verified dry-run: same primitive as a live rebuild, diff only, never writes."""
    return rebuild_projection(
        mgr, project=project, genesis_document=genesis_document, dry_run=True
    )


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
    "VerifiedAcceptance",
    "check_projection_consistent",
    "projection_summary",
    "read_lifecycle_events",
    "rebuild_projection",
    "rebuild_projection_from_trust_log",
    "rebuild_projection_from_verified_chain",
    "verify_project_acceptance",
]
