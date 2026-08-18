"""``principal_keys`` — a **projection** of signed trust-log events, not an authority.

``docs/0.6.0/TRUST-DOMAIN.md`` §5.9, as amended by ``RECONCILIATION.md`` overlay
change 3. Two rules shape this module:

1. **No verifier resolves a key from this table for a v6 event.** The table is
   retained for v4/v5 legacy verification only, where using it forces
   ``applicability = LEGACY_PARTIAL``. Consulting it for a v6 event *is* the S6
   defect (§5.11's last row).
2. **The mutators are private, event-driven appliers.** What were
   ``register_principal_key_conn`` / ``rotate_principal_key_conn`` /
   ``revoke_principal_key_conn`` (and their ``ConnectionManager``-level public
   wrappers) are now :func:`_apply_enrollment_projection`,
   :func:`_apply_rotation_projection` and :func:`_apply_revocation_projection`, each
   **requiring** a ``source_event_hash``. The public names are gone from the package
   surface, which mechanically breaks every bypass path at import rather than at
   review time (§5.9 rule 2, D-6: *documentation is not a control*).

Projection columns (migration 046): ``trust_domain_id``, ``source_event_hash``,
``acceptance_event_hash``, ``projection_version``. Post-cutover rows carry a
non-null ``source_event_hash``; pre-cutover rows keep ``NULL`` and are reported
``legacy_unsourced``. A rebuild that *empties* the legacy rows is a defect, and one
that *invents* them is worse — see :mod:`regista._trust_projection`.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from psycopg.sql import SQL, Identifier

from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError

#: Rows created by an event-driven applier. Bumped only when the projection's
#: derivation from events changes in a way that makes old rows non-reproducible.
PROJECTION_VERSION: int = 1

#: What a row with no ``source_event_hash`` is called wherever it surfaces (§5.9).
LEGACY_UNSOURCED: str = "legacy_unsourced"


@dataclass(frozen=True)
class PrincipalKeyEntry:
    principal_id: str
    key_id: str
    scheme: str
    public_key: bytes
    fingerprint: str
    status: str
    valid_from: datetime
    valid_to: datetime | None
    registered_by: str
    registered_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None
    # §5.9 projection provenance. NULL on pre-cutover rows, which are reported
    # `legacy_unsourced` and are never lifecycle evidence.
    trust_domain_id: str | None = None
    source_event_hash: str | None = None
    acceptance_event_hash: str | None = None
    projection_version: int = PROJECTION_VERSION

    @property
    def provenance(self) -> str:
        """``"v6_sourced"`` or ``"legacy_unsourced"`` (§5.9)."""
        return "v6_sourced" if self.source_event_hash is not None else LEGACY_UNSOURCED

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "key_id": self.key_id,
            "scheme": self.scheme,
            "public_key": self.public_key.hex(),
            "fingerprint": self.fingerprint,
            "status": self.status,
            "valid_from": self.valid_from.isoformat(),
            "valid_to": self.valid_to.isoformat() if self.valid_to else None,
            "registered_by": self.registered_by,
            "registered_at": self.registered_at.isoformat(),
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_reason": self.revoked_reason,
            "trust_domain_id": self.trust_domain_id,
            "source_event_hash": self.source_event_hash,
            "acceptance_event_hash": self.acceptance_event_hash,
            "projection_version": self.projection_version,
            "provenance": self.provenance,
        }


def _compute_fingerprint(public_key: bytes, scheme: str) -> str:
    return f"{scheme}:sha256:{hashlib.sha256(public_key).hexdigest()}"


def _generate_key_id() -> str:
    return f"pk_{uuid.uuid4().hex[:16]}"


def principal_entity_id(principal_id: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_OID, f"principal:{principal_id}")


def _require_source_event_hash(source_event_hash: str, applier: str) -> str:
    """Every applier is event-driven; there is no path that writes without an event.

    A caller that has no ``source_event_hash`` has no signed event, and a row written
    without one would be indistinguishable from a pre-cutover ``legacy_unsourced``
    row while actually being a post-cutover fabrication. Refused by name.
    """
    if not isinstance(source_event_hash, str) or not source_event_hash.strip():
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEYS_PROJECTION_WRITE_REFUSED,
            f"{applier} requires a non-empty source_event_hash: principal_keys is a "
            "projection of signed trust-log events (TRUST-DOMAIN.md §5.9), and a row "
            "with no source event is not a projection of anything.",
            {"reason": "source_event_hash_required", "applier": applier},
        )
    return source_event_hash


#: Tables an applier may write. The rebuild replays into a temp table so it can diff
#: against the live projection without a second, drifting copy of the applier logic;
#: the allowlist keeps that from becoming an arbitrary-table write.
_APPLIER_TABLES: frozenset[str] = frozenset(
    {"principal_keys", "_regista_principal_keys_rebuild"}
)


def _table_identifier(table: str) -> Identifier:
    if table not in _APPLIER_TABLES:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"{table!r} is not an applier target; allowed: {sorted(_APPLIER_TABLES)!r}",
            {"reason": "unknown_applier_table", "table": table},
        )
    return Identifier(table)


def _apply_enrollment_projection(
    conn: DictConn,
    principal_id: str,
    public_key: bytes,
    scheme: str,
    *,
    source_event_hash: str,
    valid_from: datetime,
    registered_at: datetime,
    valid_to: datetime | None = None,
    key_id: str | None = None,
    registered_by: str = "system",
    trust_domain_id: str | None = None,
    acceptance_event_hash: str | None = None,
    _table: str = "principal_keys",
) -> PrincipalKeyEntry:
    """Apply a ``principal_key_enrolled`` event to the projection (§5.9 rule 2).

    Private and event-driven: ``source_event_hash`` is the hash of the signed
    trust-log enrolment event this row is derived from, and is required. Formerly
    ``register_principal_key_conn``, which was a plain INSERT with no event at all
    — that function's public name is deliberately gone so the paths that called it
    break at import (§9 criterion 17).

    **Every timestamp is an argument, none is ``now()``.** ``valid_from`` is the
    payload's ``not_before``, ``valid_to`` its ``not_after``, and ``registered_at``
    the event's ``occurred_at``. A projection whose columns came from the wall clock
    could not be reproduced by a later rebuild, so criterion 12 (byte-for-byte
    rebuild) would be unsatisfiable by construction.

    Supersedes any currently-active key for the principal, setting its ``valid_to``
    to this event's ``valid_from`` — derived from the event, not from whether a code
    path remembered the UPDATE (§5.6, closing the audit's local defect 1
    structurally).
    """
    _require_source_event_hash(source_event_hash, "_apply_enrollment_projection")
    tbl = _table_identifier(_table)
    if not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id is required",
        )
    if not public_key:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "public_key is required",
        )

    if key_id is None:
        key_id = _generate_key_id()

    fingerprint = _compute_fingerprint(public_key, scheme)

    conn.execute(
        SQL("SELECT key_id FROM {} WHERE principal_id = %s FOR UPDATE").format(tbl),
        [principal_id],
    )

    existing = conn.execute(
        SQL("SELECT * FROM {} WHERE principal_id = %s AND key_id = %s").format(tbl),
        [principal_id, key_id],
    ).fetchall()

    if existing:
        row = existing[0]
        if row["status"] == "active":
            return _row_to_entry(row)
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEY_ALREADY_EXISTS,
            f"Key {key_id} already exists for principal "
            f"{principal_id} with status {row['status']}",
        )

    existing_active = conn.execute(
        SQL("SELECT key_id FROM {} WHERE principal_id = %s AND status = 'active'").format(tbl),
        [principal_id],
    ).fetchall()

    for r in existing_active:
        conn.execute(
            SQL("UPDATE {} SET status = 'superseded', valid_to = %s "
                "WHERE principal_id = %s AND key_id = %s").format(tbl),
            [valid_from, principal_id, r["key_id"]],
        )

    conn.execute(
        SQL(
            "INSERT INTO {} "
            "(principal_id, key_id, scheme, public_key, fingerprint, "
            " status, valid_from, valid_to, registered_by, registered_at, "
            " trust_domain_id, source_event_hash, "
            " acceptance_event_hash, projection_version) "
            "VALUES (%s, %s, %s, %s, %s, 'active', %s, %s, %s, %s, %s, %s, %s, %s)"
        ).format(tbl),
        [
            principal_id,
            key_id,
            scheme,
            public_key,
            fingerprint,
            valid_from,
            valid_to,
            registered_by,
            registered_at,
            trust_domain_id,
            source_event_hash,
            acceptance_event_hash,
            PROJECTION_VERSION,
        ],
    )

    row = cast(dict[str, Any], conn.execute(
        SQL("SELECT * FROM {} WHERE principal_id = %s AND key_id = %s").format(tbl),
        [principal_id, key_id],
    ).fetchone())

    return _row_to_entry(row)


def _fetch_entry(
    mgr: ConnectionManager,
    principal_id: str,
    key_id: str,
) -> PrincipalKeyEntry:
    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND key_id = %s",
            [principal_id, key_id],
        ).fetchall()
    if not rows:
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEY_NOT_FOUND,
            f"Principal key not found: {principal_id}/{key_id}",
        )
    return _row_to_entry(rows[0])


def _row_to_entry(row: dict[str, Any]) -> PrincipalKeyEntry:
    # The projection columns are read with .get() so this stays usable against a
    # schema that has not yet applied migration 046 (the read path must not break
    # a store mid-upgrade); a missing column reads as legacy_unsourced, which is
    # exactly what a pre-046 row is.
    trust_domain_id = row.get("trust_domain_id")
    return PrincipalKeyEntry(
        principal_id=row["principal_id"],
        key_id=row["key_id"],
        scheme=row["scheme"],
        public_key=bytes(row["public_key"]),
        fingerprint=row["fingerprint"],
        status=row["status"],
        valid_from=row["valid_from"],
        valid_to=row["valid_to"],
        registered_by=row["registered_by"],
        registered_at=row["registered_at"],
        revoked_at=row["revoked_at"],
        revoked_reason=row["revoked_reason"],
        trust_domain_id=str(trust_domain_id) if trust_domain_id is not None else None,
        source_event_hash=row.get("source_event_hash"),
        acceptance_event_hash=row.get("acceptance_event_hash"),
        projection_version=(
            row["projection_version"] if row.get("projection_version") is not None
            else PROJECTION_VERSION
        ),
    )


def _insert_legacy_unsourced_key(
    conn: DictConn,
    principal_id: str,
    public_key: bytes,
    scheme: str,
    *,
    key_id: str | None = None,
    registered_by: str = "legacy",
    status: str = "active",
) -> PrincipalKeyEntry:
    """Insert a **pre-cutover-shaped** row: ``source_event_hash`` stays NULL.

    This exists for one reason: the v4/v5 legacy-verification tests need registry
    rows, and the legacy epoch has no signed lifecycle events to project from
    (overlay change 3 — the dominant legacy key has no ``principal_keys`` row in any
    project and resolves only from an operator key file). Those rows are a
    *labelled compatibility input*, never lifecycle evidence.

    It is **not** a reinstated bypass. It cannot produce a v6-sourced row: the
    provenance columns are left NULL, so :func:`regista._trust_projection.rebuild`
    leaves the row alone and every surface reports it ``legacy_unsourced``. Since no
    verifier resolves a key from this table for a v6 event (§5.9 rule 1), a row
    written here can only ever affect legacy verification — which is the thing being
    tested.
    """
    if key_id is None:
        key_id = _generate_key_id()
    fingerprint = _compute_fingerprint(public_key, scheme)
    if status == "active":
        # Mirror the pre-P2.2 `register_principal_key_conn` behaviour this replaces
        # for legacy tests: a new active key supersedes the current one, closing its
        # validity window. Without this the partial unique index on
        # (principal_id) WHERE status='active' rejects the second seed, and the
        # legacy rotation-history tests would be seeding a shape the old code never
        # produced.
        from datetime import UTC, datetime

        conn.execute(
            "UPDATE principal_keys SET status = 'superseded', valid_to = %s "
            "WHERE principal_id = %s AND status = 'active'",
            [datetime.now(UTC), principal_id],
        )
    conn.execute(
        """
        INSERT INTO principal_keys
            (principal_id, key_id, scheme, public_key, fingerprint,
             status, registered_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        [principal_id, key_id, scheme, public_key, fingerprint, status, registered_by],
    )
    row = cast(dict[str, Any], conn.execute(
        "SELECT * FROM principal_keys WHERE principal_id = %s AND key_id = %s",
        [principal_id, key_id],
    ).fetchone())
    return _row_to_entry(row)


def list_principal_keys(
    mgr: ConnectionManager,
    principal_id: str | None = None,
    *,
    status: str | None = None,
) -> list[PrincipalKeyEntry]:
    query = "SELECT * FROM principal_keys WHERE 1=1"
    params: list[Any] = []
    if principal_id is not None:
        query += " AND principal_id = %s"
        params.append(principal_id)
    if status is not None:
        query += " AND status = %s"
        params.append(status)
    query += " ORDER BY registered_at DESC"
    with mgr.transaction() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_entry(r) for r in rows]


def list_principal_keys_for_conn(
    conn: DictConn,
    principal_id: str | None = None,
    *,
    status: str | None = None,
) -> list[PrincipalKeyEntry]:
    query = "SELECT * FROM principal_keys WHERE 1=1"
    params: list[Any] = []
    if principal_id is not None:
        query += " AND principal_id = %s"
        params.append(principal_id)
    if status is not None:
        query += " AND status = %s"
        params.append(status)
    query += " ORDER BY registered_at DESC"
    rows = conn.execute(query, params).fetchall()
    return [_row_to_entry(r) for r in rows]


def get_active_key(
    mgr: ConnectionManager,
    principal_id: str,
) -> PrincipalKeyEntry:
    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT * FROM principal_keys "
            "WHERE principal_id = %s AND status = 'active' "
            "ORDER BY registered_at DESC LIMIT 1",
            [principal_id],
        ).fetchall()
    if not rows:
        raise RegistaError(
            ErrorCode.UNREGISTERED_SIGNER,
            f"No active key for principal {principal_id!r}",
        )
    return _row_to_entry(rows[0])


def _apply_rotation_projection(
    conn: DictConn,
    principal_id: str,
    new_public_key: bytes,
    scheme: str,
    *,
    source_event_hash: str,
    valid_from: datetime,
    registered_at: datetime,
    valid_to: datetime | None = None,
    key_id: str | None = None,
    registered_by: str = "system",
    trust_domain_id: str | None = None,
    acceptance_event_hash: str | None = None,
    _table: str = "principal_keys",
) -> PrincipalKeyEntry:
    """Apply a ``principal_key_rotated`` event to the projection (§5.9 rule 2).

    Formerly ``rotate_principal_key_conn``. ``source_event_hash`` is required.
    Setting ``valid_to`` on the superseded key is mandatory (§5.6) and is derived
    from the event — this event's ``valid_from`` — rather than from a code path
    remembering to do it.

    ``key_id`` is accepted so a rebuild reproduces the *event's* key id rather than
    minting a fresh one; likewise every timestamp is an argument, never ``now()``. A
    rebuild that invented key ids or timestamps could not be byte-for-byte (§9
    criterion 12).
    """
    _require_source_event_hash(source_event_hash, "_apply_rotation_projection")
    tbl = _table_identifier(_table)
    if not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "principal_id is required",
        )
    if not new_public_key:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "new_public_key is required",
        )

    new_key_id = _generate_key_id() if key_id is None else key_id
    fingerprint = _compute_fingerprint(new_public_key, scheme)

    conn.execute(
        SQL("SELECT key_id FROM {} WHERE principal_id = %s FOR UPDATE").format(tbl),
        [principal_id],
    )

    conn.execute(
        SQL("UPDATE {} SET status = 'superseded', valid_to = %s "
            "WHERE principal_id = %s AND status = 'active'").format(tbl),
        [valid_from, principal_id],
    )

    conn.execute(
        SQL(
            "INSERT INTO {} "
            "(principal_id, key_id, scheme, public_key, fingerprint, "
            " status, valid_from, valid_to, registered_by, registered_at, "
            " trust_domain_id, source_event_hash, "
            " acceptance_event_hash, projection_version) "
            "VALUES (%s, %s, %s, %s, %s, 'active', %s, %s, %s, %s, %s, %s, %s, %s)"
        ).format(tbl),
        [
            principal_id,
            new_key_id,
            scheme,
            new_public_key,
            fingerprint,
            valid_from,
            valid_to,
            registered_by,
            registered_at,
            trust_domain_id,
            source_event_hash,
            acceptance_event_hash,
            PROJECTION_VERSION,
        ],
    )

    row = cast(dict[str, Any], conn.execute(
        SQL("SELECT * FROM {} WHERE principal_id = %s AND key_id = %s").format(tbl),
        [principal_id, new_key_id],
    ).fetchone())

    return _row_to_entry(row)


def _apply_revocation_projection(
    conn: DictConn,
    principal_id: str,
    key_id: str,
    *,
    source_event_hash: str,
    revoked_at: datetime,
    reason: str = "unspecified",
    _table: str = "principal_keys",
) -> PrincipalKeyEntry:
    """Apply a ``principal_key_revoked`` event to the projection (§5.9 rule 2).

    Formerly ``revoke_principal_key_conn``. ``source_event_hash`` is required, and
    identifies the revocation event; the row's own ``source_event_hash`` column is
    **not** overwritten, because §5.9 defines it as the enrolment/rotation event that
    introduced the key. Losing that would make the row unreproducible.

    ``revoked_at`` comes from the payload (§5.7 — it is a *claim*, recorded as such;
    the binding fact is the event's chain position), never from ``now()``.

    Note what this does **not** mean: flipping ``status`` here changes no verification
    outcome for any v6 event, because no verifier resolves a key from this table for
    a v6 event (§5.9 rule 1, §5.11's last row). Revocation binds at the event's
    position in the trust-log chain (§5.7), not at this row.
    """
    _require_source_event_hash(source_event_hash, "_apply_revocation_projection")
    tbl = _table_identifier(_table)
    existing = conn.execute(
        SQL("SELECT * FROM {} WHERE principal_id = %s AND key_id = %s").format(tbl),
        [principal_id, key_id],
    ).fetchall()

    if not existing:
        raise RegistaError(
            ErrorCode.PRINCIPAL_KEY_NOT_FOUND,
            f"Principal key not found: {principal_id}/{key_id}",
        )

    row = existing[0]
    if row["status"] == "revoked":
        return _row_to_entry(row)

    conn.execute(
        SQL("UPDATE {} SET status = 'revoked', revoked_at = %s, "
            "revoked_reason = %s WHERE principal_id = %s AND key_id = %s").format(tbl),
        [revoked_at, reason, principal_id, key_id],
    )

    row = cast(dict[str, Any], conn.execute(
        SQL("SELECT * FROM {} WHERE principal_id = %s AND key_id = %s").format(tbl),
        [principal_id, key_id],
    ).fetchone())

    return _row_to_entry(row)


def verify_principal_binding(
    mgr: ConnectionManager,
    principal_id: str,
    actor_id: str,
) -> PrincipalKeyEntry:
    if principal_id != actor_id:
        raise RegistaError(
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            f"Actor-signer mismatch: event actor_id={actor_id!r} "
            f"does not match signing principal_id={principal_id!r}",
        )
    return get_active_key(mgr, principal_id)
