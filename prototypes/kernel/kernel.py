"""Regista kernel prototype — the coordination contract without the trust stack.

Plan 032 F0 exit asks for "the proposed public API needed by F0a", and §5 asks
for evidence on whether to sever the trust stack out of the current kernel or
extract a corrected kernel into a fresh tree. This module is the instrument for
both: a complete create -> claim -> transition -> query -> replay path against
real PostgreSQL, with no keys, trust log, genesis ceremony or suite config.

Deliberately NOT here, because Plan 032 removes them: trust domains, principals,
key lifecycle, signing, bundles, witnesses, assurance levels, model lineage,
suite discovery, recurrence, hooks, webhooks, the HTTP sidecar.

Honest boundary, restated from Plan 032 §1 so no caller has to infer it:
  * actor_id is caller-supplied attribution. The kernel does not authenticate
    anyone. Workflow role checks enforce APPLICATION policy.
  * prev_event_hash is a consistency chain, not authenticity evidence. It
    detects accidental gaps, reordering and truncation. Anyone who can write the
    table can rewrite it.
  * A lease stops a stale worker committing to THIS store. It does not stop that
    process making external requests. Fencing external effects is the caller's
    job -- pass `attempt` to the target system too.

Three contracts this module settles explicitly, because leaving them implicit is
what produced the defects in WI-367 and WI-368. Each is stated once here and
enforced in exactly one place.

ONE CLOCK.
    The database decides what time it is, for every stamp and every expiry
    predicate. No timestamp is ever taken from the writing process: a
    coordination store has many clients and one serialization point, and if a
    client's clock decided liveness then available() and transition() could
    disagree about whether the same lease is held.

    The predicate is clock_timestamp(), NOT now(). now() is transaction_
    timestamp(): it is frozen when the transaction begins, so a liveness
    decision taken after a long wait inside an open transaction -- most
    obviously after blocking on SELECT ... FOR UPDATE -- would be evaluated
    against the clock as it was before the wait. Liveness must be decided at the
    moment the write serializes, which is after the row lock is held.
    `test_mutations.py` has a regression check that blocks a transition on a
    held row lock until the lease expires underneath it.

    Cost, stated rather than hidden: clock_timestamp() is VOLATILE, so the
    planner will not use idx_claims_expiry as a range bound the way it can with
    a stable now(). At kernel scale that is the right trade; a store large
    enough to care should revisit it with a measurement.

LEASE OWNERSHIP.
    A work item is in exactly one of three lease conditions, and every
    lease-sensitive write says which one it found:

      unclaimed   -- no row in `claims`. Writes are allowed WITHOUT an attempt.
                     Plan 032 requires a person to be able to act without first
                     taking a lease, and scenario 2 depends on it. Passing an
                     attempt here is refused (LeaseNotHeldError): the caller
                     believes it is fenced and it is not, and attempt numbers
                     are never reissued, so the number cannot be validated.
      expired     -- a row exists but clock_timestamp() is past expires_at.
                     EVERY write is refused (LeaseExpiredError), with or without
                     an attempt. Expiry is terminal: it is not a state a holder
                     can write through or heartbeat out of. The previous
                     holder's fate is unresolved until someone resolves it, and
                     doing so is one call -- expire_leases() to sweep, or
                     claim() to take over, which records the takeover as a fact.
      live        -- the write must carry the current attempt AND be attributed
                     to the holder. A wrong or absent attempt is
                     StaleAttemptError; a correct attempt presented by anyone
                     other than the holder is LeaseNotHeldError.

    The actor check is ownership, not authentication -- actor_id remains
    caller-supplied attribution and the kernel still verifies nobody's identity.
    It refuses a write ATTRIBUTED to someone who does not hold the lease,
    because recording such a write would make the history say something the
    coordination state contradicts.

FIELD TYPES.
    A custom field value, and a caller-supplied event payload value, may hold
    only: str, int, float (finite), bool, None, list, and dict with str keys,
    nested. Anything else is refused with InvalidFieldError naming the path and
    the type.

    The kernel does NOT coerce. A datetime used to raise a raw TypeError out of
    psycopg on the write path while _canonical() quietly stringified the same
    value on the hash path -- two policies on one piece of data. Coercion is the
    wrong resolution of that: the store is the source of truth for replay, and a
    silent str() means replay hands back a different type from the one the
    caller wrote, with nothing recording that it happened. Convert at the call
    site, where the intended representation is known.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import DictRow, dict_row
from psycopg.types.json import Jsonb

DictConn = psycopg.Connection[DictRow]
DictCursor = psycopg.Cursor[DictRow]

KERNEL_SCHEMA_VERSION = 1

#: Event payload keys the reducer owns. replay() reads them to rebuild state, so
#: a caller payload may not contain them -- see RESERVED_PAYLOAD_KEYS below.
RESERVED_PAYLOAD_KEYS = frozenset({"from", "to", "fields", "created"})

#: Guard against unbounded or self-referential field structures. json.dumps
#: would hit the interpreter's recursion limit and raise something unhelpful.
MAX_FIELD_DEPTH = 32

#: Exactly what replay() reconciles against the event history. Published as part
#: of the API because an empty drift list is meaningless without it: a reader
#: who takes "no drift" to mean "the whole projection matches history" would be
#: wrong, and silently so.
REPLAY_COVERS = (
    "current_state",
    "custom_fields",
    "last_event_seq",
    "event payload hashes",
    "event chain links",
    "event sequence density",
)

#: Parts of the store replay() CANNOT reconcile, because nothing appends an
#: event for them: claim(), heartbeat(), release(), expire_leases() and link()
#: all write their tables directly. Lease state, the fencing counter and typed
#: links are therefore projection-only. An empty drift list says nothing about
#: any of them.
#:
#: This is a gap against the pre-0.8 tree, which reconstructed claim state,
#: links and the attempt counter from events (src/regista/_reducer.py,
#: _links.py, tests/test_replay_coverage.py). Whether 0.8 restores that is a
#: scope decision for Plan 032, not something to paper over here. Until it is
#: ruled on, the honest position is to name it.
REPLAY_DOES_NOT_COVER = (
    "leases (claims)",
    "the attempt/fencing counter (claim_attempts)",
    "typed links (links)",
    "idempotency keys",
)


class KernelError(Exception):
    """Base class. Every refusal below is one of these, never a bare psycopg error."""


class UnsupportedSchemaError(KernelError): ...
class InvalidWorkflowError(KernelError): ...
class TransitionRefusedError(KernelError): ...
class ClaimContestedError(KernelError): ...
class StaleAttemptError(KernelError): ...
class InvalidFieldError(KernelError): ...
class IdempotencyConflictError(KernelError): ...


class LeaseExpiredError(StaleAttemptError):
    """The lease that would authorise this write is no longer live.

    Distinct from a takeover: nobody has replaced the holder yet, the lease has
    simply died. Subclasses StaleAttemptError so a caller that only wants to
    know "my fencing token is no good" keeps working.
    """


class LeaseNotHeldError(StaleAttemptError):
    """The caller presented a lease it does not hold, or none exists to hold.

    Raised when a correct attempt is attributed to someone other than the
    holder, and when an attempt is supplied for an item that has no lease at all.
    """


class ReservedPayloadKeyError(InvalidFieldError):
    """A caller payload tried to set a key the event reducer owns."""


def _check_json(value: Any, path: str, depth: int = 0) -> None:
    """Enforce the FIELD TYPES contract in the module docstring. One gate, used
    by every write path, so the stored bytes and the hashed bytes cannot
    disagree about what a value is."""
    if depth > MAX_FIELD_DEPTH:
        raise InvalidFieldError(
            f"{path}: nested deeper than {MAX_FIELD_DEPTH} levels (or self-referential)"
        )
    if value is None or isinstance(value, (str, bool, int)):
        return  # bool before int is unnecessary here: both are accepted.
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise InvalidFieldError(
                f"{path}: {value!r} has no JSON representation and PostgreSQL jsonb "
                "rejects it. Store a string or null if you need to record it."
            )
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            _check_json(v, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise InvalidFieldError(
                    f"{path}: object keys must be strings, found "
                    f"{type(k).__name__} {k!r} (json.dumps would silently rename it)"
                )
            _check_json(v, f"{path}.{k}", depth + 1)
        return
    raise InvalidFieldError(
        f"{path}: {type(value).__name__} is not a supported field type. A field may "
        "hold only JSON types: string, number, boolean, null, list, or object with "
        "string keys. The kernel refuses rather than coercing, because a silent "
        "conversion makes replay return a different type from the one you wrote. "
        "Convert at the call site: datetime -> .isoformat(), UUID/Decimal -> str(), "
        "tuple/set -> list()."
    )


def _check_mapping(obj: dict[str, Any] | None, label: str) -> None:
    for k, v in (obj or {}).items():
        if not isinstance(k, str):
            raise InvalidFieldError(
                f"{label}: names must be strings, found {type(k).__name__} {k!r}"
            )
        _check_json(v, f"{label}.{k}")


def _canonical(obj: object) -> bytes:
    """Deterministic JSON bytes. Sorted keys, no incidental whitespace.

    No `default=`: everything reaching here has passed _check_json, so a
    TypeError from this function means a write path skipped the gate, which is a
    bug worth seeing rather than stringifying away.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _jsonb(obj: dict[str, Any]) -> Jsonb:
    """Store with the same policy _canonical() hashes with."""
    return Jsonb(obj, dumps=lambda o: json.dumps(o, allow_nan=False))


def _hash(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


@dataclass(frozen=True)
class Workflow:
    """An immutable registered workflow version.

    states:      the closed set of states an item may occupy.
    initial:     the state a new item starts in.
    transitions: name -> (from_states, to_state).
    roles:       transition name -> the set of roles allowed to perform it.
                 Application policy. The kernel checks the caller's claimed role
                 against it; it does not verify that the caller holds that role.
    required_fields: transition name -> field names that must be present on the
                 item (already set, or supplied with this transition).
    terminal:    states from which nothing may follow.
    """

    name: str
    version: int
    states: tuple[str, ...]
    initial: str
    transitions: dict[str, tuple[tuple[str, ...], str]]
    roles: dict[str, tuple[str, ...]] = field(default_factory=dict)
    required_fields: dict[str, tuple[str, ...]] = field(default_factory=dict)
    terminal: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.states:
            raise InvalidWorkflowError("a workflow needs at least one state")
        if self.initial not in self.states:
            raise InvalidWorkflowError(f"initial state {self.initial!r} is not in states")
        for t, (froms, to) in self.transitions.items():
            for f in froms:
                if f not in self.states:
                    raise InvalidWorkflowError(f"transition {t!r} leaves unknown state {f!r}")
            if to not in self.states:
                raise InvalidWorkflowError(f"transition {t!r} enters unknown state {to!r}")
        for s in self.terminal:
            if s not in self.states:
                raise InvalidWorkflowError(f"terminal state {s!r} is not in states")
        for t in list(self.roles) + list(self.required_fields):
            if t not in self.transitions:
                raise InvalidWorkflowError(f"policy names unknown transition {t!r}")

    def as_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "states": list(self.states),
            "initial": self.initial,
            "transitions": {k: [list(v[0]), v[1]] for k, v in self.transitions.items()},
            "roles": {k: list(v) for k, v in self.roles.items()},
            "required_fields": {k: list(v) for k, v in self.required_fields.items()},
            "terminal": list(self.terminal),
        }

    @staticmethod
    def from_json(d: dict[str, Any], version: int) -> Workflow:
        return Workflow(
            name=d["name"],
            version=version,
            states=tuple(d["states"]),
            initial=d["initial"],
            transitions={k: (tuple(v[0]), v[1]) for k, v in d["transitions"].items()},
            roles={k: tuple(v) for k, v in d.get("roles", {}).items()},
            required_fields={k: tuple(v) for k, v in d.get("required_fields", {}).items()},
            terminal=tuple(d.get("terminal", [])),
        )


@dataclass(frozen=True)
class WorkItem:
    id: uuid.UUID
    workflow_name: str
    workflow_version: int
    type: str
    state: str
    fields: dict[str, Any]
    last_event_seq: int


@dataclass(frozen=True)
class Claim:
    """A durable lease. `attempt` is the fencing token."""

    work_item_id: uuid.UUID
    actor_id: str
    attempt: int
    expires_at: datetime


@dataclass(frozen=True)
class Event:
    seq: int
    actor_id: str
    actor_kind: str
    transition: str | None
    payload: dict[str, Any]
    occurred_at: datetime


class Kernel:
    """Coordination state over one PostgreSQL schema.

    The caller owns execution and interfaces; this owns who holds what, what
    state it is in, what may happen next, and how it got there.
    """

    def __init__(self, conn: DictConn, schema: str) -> None:
        self._conn = conn
        self._schema = schema

    # ---- lifecycle -------------------------------------------------------

    @classmethod
    def connect(cls, dsn: str, *, schema: str = "public") -> Kernel:
        conn: DictConn = psycopg.connect(dsn, row_factory=dict_row, autocommit=False)
        with conn.cursor() as cur:
            cur.execute(f'SET search_path TO "{schema}"')
        # SET is undone by a rollback, so this must commit rather than leave the
        # transaction open: initialize() rolls back when it refuses a schema, and
        # that would otherwise silently drop the connection back to the default
        # search_path for the rest of the session.
        conn.commit()
        return cls(conn, schema)

    def close(self) -> None:
        self._conn.close()

    def _end_read(self) -> None:
        """Close a read-only transaction.

        Rollback rather than commit, because nothing was written and saying so
        is more honest. Leaving it open pins the transaction snapshot and, on
        the old now()-based predicates, pinned the clock too.
        """
        self._conn.rollback()

    def _db_now(self, cur: DictCursor) -> datetime:
        """The one clock. See ONE CLOCK in the module docstring."""
        cur.execute("SELECT clock_timestamp() AS ts")
        row = cur.fetchone()
        if row is None:  # pragma: no cover - a scalar SELECT always returns a row
            raise KernelError("the database did not return a timestamp")
        ts: datetime = row["ts"]
        return ts

    def initialize(self, schema_sql_path: str) -> None:
        """Create the kernel schema in an empty destination.

        Distinguishes the three cases Plan 032 F1 requires: a supported new
        schema (no-op), an empty destination (create), and an old or unknown
        schema (refuse WITHOUT mutating anything).
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = %s",
                (self._schema,),
            )
            tables = {r["table_name"] for r in cur.fetchall()}

            if "kernel_meta" in tables:
                cur.execute("SELECT kernel_schema_version FROM kernel_meta")
                row = cur.fetchone()
                found = row["kernel_schema_version"] if row else None
                if found == KERNEL_SCHEMA_VERSION:
                    self._conn.commit()
                    return
                self._conn.rollback()
                raise UnsupportedSchemaError(
                    f"kernel schema version {found} is not supported "
                    f"(this build speaks {KERNEL_SCHEMA_VERSION}). Nothing was changed. "
                    "In-place upgrades are not supported; use a fresh database."
                )

            # Any pre-0.8 regista schema, or anything else with tables present.
            if tables:
                legacy = tables & {
                    "events", "work_items_current", "project_identity",
                    "_regista_migrations", "_substrate_migrations", "principal_keys",
                }
                self._conn.rollback()
                raise UnsupportedSchemaError(
                    f"destination schema {self._schema!r} is not empty and is not a "
                    f"kernel schema (found {sorted(legacy) or sorted(tables)[:5]}). "
                    "Nothing was changed. 0.8 is a deliberate break: there is no "
                    "in-place upgrade from 0.7.2 or earlier. Point this at a fresh "
                    "database and keep the old one for reference."
                )

            with open(schema_sql_path) as fh:
                cur.execute(fh.read())
            cur.execute(
                "INSERT INTO kernel_meta (kernel_schema_version) VALUES (%s)",
                (KERNEL_SCHEMA_VERSION,),
            )
        self._conn.commit()

    # ---- workflows -------------------------------------------------------

    def register_workflow(self, wf: Workflow) -> int:
        """Register an immutable workflow version. Idempotent for identical content."""
        wf.validate()
        body = wf.as_json()
        content_hash = _hash(_canonical(body))
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT version, content_hash FROM workflow_registry "
                "WHERE workflow_name = %s ORDER BY version DESC LIMIT 1",
                (wf.name,),
            )
            row = cur.fetchone()
            if row and bytes(row["content_hash"]) == content_hash:
                self._conn.commit()
                return int(row["version"])
            version = (int(row["version"]) + 1) if row else 1
            cur.execute(
                "INSERT INTO workflow_registry (workflow_name, version, definition, content_hash) "
                "VALUES (%s, %s, %s, %s)",
                (wf.name, version, _jsonb(body), content_hash),
            )
        self._conn.commit()
        return version

    def _read_workflow(self, cur: DictCursor, name: str, version: int | None) -> Workflow:
        """Workflow lookup INSIDE a caller's transaction.

        Separate from get_workflow() because that one ends its transaction, and
        transition() calls this while holding SELECT ... FOR UPDATE on the work
        item. Ending the transaction there would drop the row lock mid-write.
        """
        if version is None:
            cur.execute(
                "SELECT version, definition FROM workflow_registry "
                "WHERE workflow_name = %s ORDER BY version DESC LIMIT 1",
                (name,),
            )
        else:
            cur.execute(
                "SELECT version, definition FROM workflow_registry "
                "WHERE workflow_name = %s AND version = %s",
                (name, version),
            )
        row = cur.fetchone()
        if not row:
            cur.execute(
                "SELECT DISTINCT workflow_name FROM workflow_registry ORDER BY workflow_name"
            )
            known = [r["workflow_name"] for r in cur.fetchall()]
            raise InvalidWorkflowError(
                f"no such workflow: {name!r} v{version}. Registered: {known or 'none'} "
                "(see list_workflows(); register one with register_workflow(Workflow(...)))"
            )
        return Workflow.from_json(row["definition"], int(row["version"]))

    def get_workflow(self, name: str, version: int | None = None) -> Workflow:
        with self._conn.cursor() as cur:
            try:
                wf = self._read_workflow(cur, name, version)
            finally:
                self._end_read()
        return wf

    def list_workflows(self) -> list[tuple[str, int, datetime]]:
        """Every registered workflow version, oldest first."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT workflow_name, version, registered_at FROM workflow_registry "
                "ORDER BY workflow_name, version"
            )
            rows = cur.fetchall()
        self._end_read()
        return [(r["workflow_name"], int(r["version"]), r["registered_at"]) for r in rows]

    def health(self) -> dict[str, Any]:
        """Schema version and bounded counts. Cheap enough to poll."""
        with self._conn.cursor() as cur:
            cur.execute("SELECT kernel_schema_version FROM kernel_meta")
            row = cur.fetchone()
            version = int(row["kernel_schema_version"]) if row else None
            counts = {}
            for label, sql in (
                ("work_items", "SELECT count(*) AS n FROM work_items_current"),
                ("live_leases",
                 "SELECT count(*) AS n FROM claims WHERE expires_at > clock_timestamp()"),
                ("events", "SELECT count(*) AS n FROM events"),
                ("workflows", "SELECT count(*) AS n FROM workflow_registry"),
            ):
                cur.execute(sql)
                r = cur.fetchone()
                counts[label] = int(r["n"]) if r else 0
        self._end_read()
        return {"schema_version": version, **counts}

    # ---- work items ------------------------------------------------------

    def create_work_item(
        self,
        *,
        workflow: str,
        type: str,
        actor_id: str,
        actor_kind: str = "agent",
        fields: dict[str, Any] | None = None,
        workflow_version: int | None = None,
    ) -> WorkItem:
        fields = dict(fields or {})
        _check_mapping(fields, "fields")
        with self._conn.cursor() as cur:
            wf = self._read_workflow(cur, workflow, workflow_version)
            item_id = uuid.uuid4()
            now = self._db_now(cur)
            cur.execute(
                # created_at is given explicitly rather than left to its DEFAULT so
                # that the row, its last_event_at and its creation event all carry
                # ONE database instant instead of three clock_timestamp() reads
                # microseconds apart.
                "INSERT INTO work_items_current (work_item_id, workflow_name, workflow_version, "
                "work_item_type, current_state, custom_fields, last_event_seq, next_event_seq, "
                "last_event_at, created_at) VALUES (%s, %s, %s, %s, %s, %s, 0, 1, %s, %s)",
                (item_id, wf.name, wf.version, type, wf.initial, _jsonb(fields), now, now),
            )
            cur.execute(
                "INSERT INTO claim_attempts (work_item_id, last_attempt) VALUES (%s, 0)",
                (item_id,),
            )
            self._append_event(
                cur, item_id, seq=0, actor_id=actor_id, actor_kind=actor_kind,
                transition=None,
                payload={"created": {"workflow": wf.name, "version": wf.version,
                                     "type": type, "state": wf.initial, "fields": fields}},
                occurred_at=now,
            )
        self._conn.commit()
        return WorkItem(item_id, wf.name, wf.version, type, wf.initial, fields, 0)

    def get(self, work_item_id: uuid.UUID) -> WorkItem:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM work_items_current WHERE work_item_id = %s", (work_item_id,)
            )
            row = cur.fetchone()
        self._end_read()
        if not row:
            raise KernelError(f"no such work item: {work_item_id}")
        return WorkItem(
            row["work_item_id"], row["workflow_name"], row["workflow_version"],
            row["work_item_type"], row["current_state"], row["custom_fields"],
            row["last_event_seq"],
        )

    # ---- claims ----------------------------------------------------------

    def claim(
        self, work_item_id: uuid.UUID, *, actor_id: str, ttl_seconds: float = 300
    ) -> Claim:
        """Acquire a lease, taking over an expired one. Refuses a live foreign lease."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT work_item_id FROM work_items_current WHERE work_item_id = %s FOR UPDATE",
                (work_item_id,),
            )
            if not cur.fetchone():
                self._conn.rollback()
                raise KernelError(f"no such work item: {work_item_id}")
            # clock_timestamp(), evaluated after the row lock is held: see ONE
            # CLOCK. now() here would be the clock as of before any lock wait.
            cur.execute(
                "SELECT actor_id, expires_at, expires_at > clock_timestamp() AS live "
                "FROM claims WHERE work_item_id = %s",
                (work_item_id,),
            )
            existing = cur.fetchone()
            if existing and existing["live"]:
                holder = existing["actor_id"]
                self._conn.rollback()
                raise ClaimContestedError(
                    f"work item {work_item_id} is held by {holder!r} until "
                    f"{existing['expires_at'].isoformat()}"
                )
            cur.execute(
                "UPDATE claim_attempts SET last_attempt = last_attempt + 1 "
                "WHERE work_item_id = %s RETURNING last_attempt",
                (work_item_id,),
            )
            attempt_row = cur.fetchone()
            if attempt_row is None:
                self._conn.rollback()
                raise KernelError(
                    f"claim_attempts row missing for {work_item_id}; the work item was "
                    "removed concurrently"
                )
            attempt = int(attempt_row["last_attempt"])
            cur.execute(
                "INSERT INTO claims (work_item_id, actor_id, attempt_number, "
                "acquired_at, expires_at) "
                "VALUES (%s, %s, %s, clock_timestamp(), "
                "clock_timestamp() + make_interval(secs => %s)) "
                "ON CONFLICT (work_item_id) DO UPDATE SET actor_id = EXCLUDED.actor_id, "
                "attempt_number = EXCLUDED.attempt_number, acquired_at = EXCLUDED.acquired_at, "
                "expires_at = EXCLUDED.expires_at "
                "RETURNING expires_at",
                (work_item_id, actor_id, attempt, float(ttl_seconds)),
            )
            claim_row = cur.fetchone()
            if claim_row is None:  # pragma: no cover - RETURNING always yields a row here
                self._conn.rollback()
                raise KernelError(f"failed to record the lease for {work_item_id}")
            expires = claim_row["expires_at"]
        self._conn.commit()
        return Claim(work_item_id, actor_id, attempt, expires)

    def heartbeat(
        self, work_item_id: uuid.UUID, *, actor_id: str, attempt: int,
        ttl_seconds: float = 300,
    ) -> Claim:
        """Extend a LIVE lease. Expiry is terminal -- a dead lease is never revived.

        Renewing an expired lease would let a worker that slept past its TTL
        silently race a legitimate takeover: available() would already have
        offered the item to someone else.

        Takes the same primitives as release(), for the same reason F0a §4(b)
        reshaped release(): a process that did not itself call claim() holds
        only (id, actor, attempt), and making it fabricate a Claim with an
        invented expires_at is a lie the type system has to be silenced about.
        A library caller holding a Claim unpacks it:

            k.heartbeat(c.work_item_id, actor_id=c.actor_id, attempt=c.attempt)
        """
        with self._conn.cursor() as cur:
            # Serialize on the same row claim() and transition() lock, in the same
            # order, so the whole lease state machine has ONE serialization point.
            # Without it, a heartbeat and a takeover can both believe they won: the
            # takeover reads an expired lease, the heartbeat extends it just before
            # expiry, and the takeover's upsert then overwrites a lease the holder
            # was told it still had. The fencing token still protects the store, but
            # heartbeat would have returned success to a superseded holder.
            cur.execute(
                "SELECT work_item_id FROM work_items_current WHERE work_item_id = %s "
                "FOR UPDATE",
                (work_item_id,),
            )
            if not cur.fetchone():
                self._conn.rollback()
                raise KernelError(f"no such work item: {work_item_id}")
            cur.execute(
                "UPDATE claims SET expires_at = clock_timestamp() + make_interval(secs => %s) "
                "WHERE work_item_id = %s AND actor_id = %s AND attempt_number = %s "
                "AND expires_at > clock_timestamp() "
                "RETURNING expires_at",
                (float(ttl_seconds), work_item_id, actor_id, attempt),
            )
            row = cur.fetchone()
            if not row:
                cur.execute(
                    "SELECT actor_id, attempt_number, expires_at, "
                    "expires_at > clock_timestamp() AS live "
                    "FROM claims WHERE work_item_id = %s",
                    (work_item_id,),
                )
                current = cur.fetchone()
                self._conn.rollback()
                raise self._lease_refusal(work_item_id, current, actor_id,
                                          attempt, verb="heartbeat")
            expires = row["expires_at"]
        self._conn.commit()
        return Claim(work_item_id, actor_id, attempt, expires)

    @staticmethod
    def _lease_refusal(
        work_item_id: uuid.UUID, current: DictRow | None, actor_id: str,
        attempt: int | None, *, verb: str,
    ) -> StaleAttemptError:
        """Name which of the three lease conditions the caller actually hit.

        A single "your lease is no good" message cannot tell a worker that slept
        past its TTL from one that was replaced, and those need different
        responses: the first may take the item over, the second must not.
        """
        if current is None:
            return LeaseNotHeldError(
                f"{verb} refused: there is no lease on {work_item_id}, so attempt "
                f"{attempt} cannot be honoured. It was released or swept, and attempt "
                "numbers are never reissued. Call claim() to take a fresh lease; an "
                "unclaimed item also accepts writes with no attempt at all."
            )
        if not current["live"]:
            return LeaseExpiredError(
                f"{verb} refused: the lease on {work_item_id} (attempt "
                f"{current['attempt_number']}, held by {current['actor_id']!r}) expired at "
                f"{current['expires_at'].isoformat()}. Expiry is terminal -- it cannot be "
                "renewed or written through. Call expire_leases() to sweep it, or claim() "
                "to take it over and record the takeover."
            )
        if int(current["attempt_number"]) != (attempt if attempt is not None else -1):
            return StaleAttemptError(
                f"{verb} refused: attempt {attempt} is stale. The current lease on "
                f"{work_item_id} is attempt {current['attempt_number']}, held by "
                f"{current['actor_id']!r} until {current['expires_at'].isoformat()}. "
                "Someone else took over."
            )
        return LeaseNotHeldError(
            f"{verb} refused: attempt {attempt} on {work_item_id} is held by "
            f"{current['actor_id']!r}, not {actor_id!r}. A write must be attributed to "
            "the lease holder. (This is ownership, not authentication: actor_id is "
            "caller-supplied attribution either way.)"
        )

    def release(self, work_item_id: uuid.UUID, *, actor_id: str, attempt: int) -> None:
        """Release a lease. Takes the primitive rather than a Claim, so a CLI
        holding only (id, actor, attempt) can call it without fabricating one.

        Releasing an already-dead or already-replaced lease is a no-op, not a
        refusal: release is cleanup, and cleanup that raises makes callers wrap
        it in a bare except.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "DELETE FROM claims WHERE work_item_id = %s AND actor_id = %s "
                "AND attempt_number = %s",
                (work_item_id, actor_id, attempt),
            )
        self._conn.commit()

    def expire_leases(self) -> int:
        """Sweep expired leases. Returns how many were removed."""
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM claims WHERE expires_at <= clock_timestamp()")
            n = cur.rowcount
        self._conn.commit()
        return n

    # ---- transitions -----------------------------------------------------

    def transition(
        self,
        work_item_id: uuid.UUID,
        *,
        transition: str,
        actor_id: str,
        actor_kind: str = "agent",
        role: str | None = None,
        attempt: int | None = None,
        fields: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> WorkItem:
        """Make a validated transition.

        `attempt` is the fencing token from claim(). See LEASE OWNERSHIP in the
        module docstring for the full rule; in short, a live lease requires the
        current attempt AND the holder's actor_id, an expired lease refuses
        everything until it is swept or taken over, and an unclaimed item
        accepts a write with no attempt.

        `fields` are the caller's domain data, merged into the item. `payload`
        is free-form annotation recorded on the event. Both obey the FIELD TYPES
        contract, and `payload` may not contain a reserved key.
        """
        fields = dict(fields or {})
        payload = dict(payload or {})
        _check_mapping(fields, "fields")
        _check_mapping(payload, "payload")
        reserved = sorted(RESERVED_PAYLOAD_KEYS & set(payload))
        if reserved:
            # Refuse rather than namespace. Namespacing (payload -> {"caller": ...})
            # would silently relocate the caller's data and change the on-disk
            # event shape that history() readers and replay() both depend on.
            # A refusal is a stable contract, visible at the call site, and it
            # keeps the event payload flat enough for a person to read.
            raise ReservedPayloadKeyError(
                f"payload may not set {reserved}: {sorted(RESERVED_PAYLOAD_KEYS)} are "
                "written by the event reducer and read back by replay(). Overwriting "
                "one makes the history disagree with the projection. Use a different "
                "key, or pass domain data as fields=."
            )
        request_hash = _hash(_canonical({
            "w": str(work_item_id), "t": transition, "a": actor_id,
            "f": fields, "p": payload,
        }))
        with self._conn.cursor() as cur:
            if idempotency_key is not None:
                cur.execute(
                    "SELECT work_item_id, request_hash FROM idempotency_keys "
                    "WHERE idempotency_key = %s",
                    (idempotency_key,),
                )
                prior = cur.fetchone()
                if prior:
                    if bytes(prior["request_hash"]) != request_hash:
                        self._conn.rollback()
                        raise IdempotencyConflictError(
                            f"idempotency key {idempotency_key!r} was used for a different "
                            "request; refusing without partial effect"
                        )
                    self._conn.rollback()
                    return self.get(work_item_id)

            cur.execute(
                "SELECT * FROM work_items_current WHERE work_item_id = %s FOR UPDATE",
                (work_item_id,),
            )
            item = cur.fetchone()
            if not item:
                self._conn.rollback()
                raise KernelError(f"no such work item: {work_item_id}")

            wf = self._read_workflow(cur, item["workflow_name"], item["workflow_version"])

            # Lease fencing, before any validation that could leak state.
            # clock_timestamp(), not now(): the row lock above may have blocked
            # for longer than the lease had left, and the write serializes HERE,
            # not when this transaction began.
            cur.execute(
                "SELECT actor_id, attempt_number, expires_at, "
                "expires_at > clock_timestamp() AS live "
                "FROM claims WHERE work_item_id = %s",
                (work_item_id,),
            )
            lease = cur.fetchone()
            if lease is None:
                # Unclaimed. Writes without an attempt are deliberate and allowed.
                if attempt is not None:
                    self._conn.rollback()
                    raise self._lease_refusal(work_item_id, None, actor_id, attempt,
                                              verb="transition")
            elif not lease["live"]:
                self._conn.rollback()
                raise self._lease_refusal(work_item_id, lease, actor_id, attempt,
                                          verb="transition")
            else:
                if attempt is None:
                    self._conn.rollback()
                    raise StaleAttemptError(
                        f"transition refused: work item {work_item_id} is under a live lease "
                        f"(attempt {lease['attempt_number']}, held by {lease['actor_id']!r}). "
                        "A lease-protected write must carry the fencing token as the attempt= "
                        f"argument: transition(..., actor_id={lease['actor_id']!r}, "
                        f"attempt={lease['attempt_number']}). claim() returns it as "
                        "Claim.attempt."
                    )
                if (int(attempt) != int(lease["attempt_number"])
                        or actor_id != lease["actor_id"]):
                    self._conn.rollback()
                    raise self._lease_refusal(work_item_id, lease, actor_id, attempt,
                                              verb="transition")

            state = item["current_state"]
            if state in wf.terminal:
                self._conn.rollback()
                raise TransitionRefusedError(f"{state!r} is terminal; no transition may follow")
            if transition not in wf.transitions:
                self._conn.rollback()
                raise TransitionRefusedError(
                    f"{transition!r} is not a transition of {wf.name} v{wf.version} "
                    f"(known: {sorted(wf.transitions)})"
                )
            froms, to = wf.transitions[transition]
            if state not in froms:
                from_here = sorted(n for n, (f, _) in wf.transitions.items() if state in f)
                self._conn.rollback()
                raise TransitionRefusedError(
                    f"{transition!r} leaves {sorted(froms)}, but the item is in {state!r}. "
                    f"From {state!r} you can: {from_here or 'nothing'}"
                )
            allowed = wf.roles.get(transition)
            if allowed and (role is None or role not in allowed):
                self._conn.rollback()
                raise TransitionRefusedError(
                    f"{transition!r} is restricted to roles {sorted(allowed)}; the caller "
                    f"presented role={role!r}. Pass one as the role= argument, e.g. "
                    f"transition(..., role={sorted(allowed)[0]!r}). The kernel checks the "
                    "role you present against the workflow; it does not verify you hold it."
                )

            merged = dict(item["custom_fields"])
            merged.update(fields)
            missing = [f for f in wf.required_fields.get(transition, ()) if f not in merged]
            if missing:
                self._conn.rollback()
                example = ", ".join(f"{m!r}: ..." for m in missing)
                raise InvalidFieldError(
                    f"{transition!r} requires field(s) {missing} to be set on the item, "
                    f"and they are not. Supply them with this transition using the "
                    f"fields= argument: transition(..., fields={{{example}}})"
                )

            seq = int(item["next_event_seq"])
            now = self._db_now(cur)
            # The reducer's keys go LAST so a caller payload cannot displace
            # them. The refusal above means this can no longer collide, and the
            # ordering is the belt to that braces.
            event_id = self._append_event(
                cur, work_item_id, seq=seq, actor_id=actor_id, actor_kind=actor_kind,
                transition=transition,
                payload={**payload, "from": state, "to": to, "fields": fields},
                occurred_at=now,
            )
            cur.execute(
                "UPDATE work_items_current SET current_state = %s, custom_fields = %s, "
                "last_event_seq = %s, next_event_seq = %s, last_event_at = %s "
                "WHERE work_item_id = %s",
                (to, _jsonb(merged), seq, seq + 1, now, work_item_id),
            )
            if idempotency_key is not None:
                cur.execute(
                    "INSERT INTO idempotency_keys (idempotency_key, work_item_id, event_id, "
                    "request_hash) VALUES (%s, %s, %s, %s)",
                    (idempotency_key, work_item_id, event_id, request_hash),
                )
        self._conn.commit()
        # Return what THIS call committed, not a re-read: a re-read would report
        # a concurrent writer's later state as if it were this transition's result.
        return WorkItem(work_item_id, wf.name, wf.version, item["work_item_type"],
                        to, merged, seq)

    def _append_event(
        self, cur: DictCursor, work_item_id: uuid.UUID, *, seq: int, actor_id: str,
        actor_kind: str, transition: str | None, payload: dict[str, Any],
        occurred_at: datetime,
    ) -> uuid.UUID:
        """Append one event, chained to its predecessor for CONSISTENCY only.

        `occurred_at` must be a database-generated timestamp (see _db_now); it
        is passed in rather than taken here so the event and the projection row
        it updates carry exactly the same instant.
        """
        cur.execute(
            "SELECT payload_hash, prev_event_hash FROM events WHERE work_item_id = %s "
            "ORDER BY event_seq DESC LIMIT 1",
            (work_item_id,),
        )
        prev = cur.fetchone()
        prev_hash = (
            _hash(bytes(prev["payload_hash"]), bytes(prev["prev_event_hash"] or b""))
            if prev else None
        )
        payload_hash = _hash(_canonical(payload))
        event_id = uuid.uuid4()
        cur.execute(
            "INSERT INTO events (event_id, work_item_id, event_seq, actor_id, actor_kind, "
            "transition, payload, payload_hash, prev_event_hash, occurred_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (event_id, work_item_id, seq, actor_id, actor_kind, transition,
             _jsonb(payload), payload_hash, prev_hash, occurred_at),
        )
        return event_id

    # ---- links -----------------------------------------------------------

    def link(self, source: uuid.UUID, target: uuid.UUID, link_type: str) -> None:
        if source == target:
            raise InvalidFieldError("a work item cannot link to itself")
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO links (source_id, target_id, link_type) VALUES (%s, %s, %s) "
                "ON CONFLICT DO NOTHING",
                (source, target, link_type),
            )
        self._conn.commit()

    def links_from(self, source: uuid.UUID) -> list[tuple[uuid.UUID, str]]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT target_id, link_type FROM links WHERE source_id = %s "
                "ORDER BY link_type, target_id",
                (source,),
            )
            rows = cur.fetchall()
        self._end_read()
        return [(r["target_id"], r["link_type"]) for r in rows]

    # ---- discovery queries ----------------------------------------------

    def available(self, *, workflow: str | None = None, states: tuple[str, ...] = (),
                  limit: int = 50) -> list[WorkItem]:
        """Items in the given states with no live lease. Ordered oldest-first."""
        sql = [
            "SELECT w.* FROM work_items_current w",
            "LEFT JOIN claims c ON c.work_item_id = w.work_item_id "
            "AND c.expires_at > clock_timestamp()",
            "WHERE c.work_item_id IS NULL",
        ]
        args: list[Any] = []
        if workflow:
            sql.append("AND w.workflow_name = %s")
            args.append(workflow)
        if states:
            sql.append("AND w.current_state = ANY(%s)")
            args.append(list(states))
        sql.append("ORDER BY w.created_at, w.work_item_id LIMIT %s")
        args.append(limit)
        return self._query(" ".join(sql), args)

    def owned(self, actor_id: str, *, limit: int = 50) -> list[WorkItem]:
        return self._query(
            "SELECT w.* FROM work_items_current w JOIN claims c USING (work_item_id) "
            "WHERE c.actor_id = %s AND c.expires_at > clock_timestamp() "
            "ORDER BY w.created_at, w.work_item_id LIMIT %s",
            [actor_id, limit],
        )

    def in_states(self, states: tuple[str, ...], *, limit: int = 50) -> list[WorkItem]:
        """The general form behind 'review-ready' and 'blocked'.

        Plan 032: these are QUERIES over the caller's workflow, not a mandatory
        canonical workflow or an inferred scheduling policy.
        """
        return self._query(
            "SELECT * FROM work_items_current WHERE current_state = ANY(%s) "
            "ORDER BY created_at, work_item_id LIMIT %s",
            [list(states), limit],
        )

    def _query(self, sql: str, args: list[Any]) -> list[WorkItem]:
        with self._conn.cursor() as cur:
            cur.execute(sql, args)
            rows = cur.fetchall()
        self._end_read()
        return [
            WorkItem(r["work_item_id"], r["workflow_name"], r["workflow_version"],
                     r["work_item_type"], r["current_state"], r["custom_fields"],
                     r["last_event_seq"])
            for r in rows
        ]

    # ---- history and replay ---------------------------------------------

    def history(self, work_item_id: uuid.UUID) -> list[Event]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM events WHERE work_item_id = %s ORDER BY event_seq",
                (work_item_id,),
            )
            rows = cur.fetchall()
        self._end_read()
        return [
            Event(r["event_seq"], r["actor_id"], r["actor_kind"], r["transition"],
                  r["payload"], r["occurred_at"])
            for r in rows
        ]

    def replay(self, work_item_id: uuid.UUID) -> tuple[str, dict[str, Any], list[str]]:
        """Rebuild state from events alone and reconcile it with the projection.

        Returns (state, fields, drift). Drift is reported honestly rather than
        raised: replay's job is to say what the history supports and where it
        disagrees with the projection.

        What is checked, exactly -- the whole of the supported projection, not
        just the state:
          * every event's payload against its recorded payload_hash;
          * every chain link against its predecessor;
          * sequence numbers dense from 0;
          * replayed state vs current_state;
          * replayed custom fields vs custom_fields;
          * the final event's seq vs last_event_seq, which is what catches a
            truncated tail -- deleting the last event of a transition that
            changed only fields moves neither the state nor the chain.

        What is NOT checked, and why an empty drift list is a NARROW statement:

          * Anything in REPLAY_DOES_NOT_COVER -- leases, the fencing counter,
            typed links, idempotency keys. Nothing appends an event for those,
            so there is no history to reconcile them against. "No drift" means
            "the reconstructible projection matches"; it does not mean "the
            store matches its history".
          * A rewrite that changes the events AND the projection consistently.
            The chain is unkeyed, so anyone who can write these tables can write
            a history that reconciles. See the module docstring.

        The whole reconciliation runs against ONE repeatable-read snapshot.
        Reading events and the projection in separate transactions would let a
        concurrent transition land between them and be reported as drift.
        """
        self._conn.rollback()  # guarantee the isolation level applies to a fresh transaction
        with self._conn.cursor() as cur:
            cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cur.execute(
                "SELECT event_seq, transition, payload, payload_hash, prev_event_hash "
                "FROM events WHERE work_item_id = %s ORDER BY event_seq",
                (work_item_id,),
            )
            rows = cur.fetchall()
            cur.execute(
                "SELECT current_state, custom_fields, last_event_seq "
                "FROM work_items_current WHERE work_item_id = %s",
                (work_item_id,),
            )
            projection = cur.fetchone()
        self._end_read()

        drift: list[str] = []
        if not rows:
            return ("", {}, ["no events"])

        state: str = ""
        fields: dict[str, Any] = {}
        running: bytes | None = None
        for i, r in enumerate(rows):
            seq = int(r["event_seq"])
            payload = r["payload"]
            if seq != i:
                drift.append(f"sequence gap: expected {i}, found {seq}")
            if r["transition"] is None:
                created = payload.get("created", {})
                state = created.get("state", "")
                fields = dict(created.get("fields", {}))
            else:
                if payload.get("from") != state:
                    drift.append(
                        f"event {seq} leaves {payload.get('from')!r} "
                        f"but replay is in {state!r}"
                    )
                state = payload.get("to", state)
                fields.update(payload.get("fields", {}))

            # Chain check. Consistency only -- see the module docstring.
            if bytes(r["payload_hash"]) != _hash(_canonical(payload)):
                drift.append(f"event {seq}: payload does not match its hash")
            stored = bytes(r["prev_event_hash"]) if r["prev_event_hash"] is not None else None
            if stored != running:
                drift.append(f"event {seq}: chain link does not match predecessor")
            running = _hash(bytes(r["payload_hash"]), bytes(stored or b""))

        if projection is None:
            drift.append("the projection row is missing, but events exist for this item")
            return (state, fields, drift)

        if projection["current_state"] != state:
            drift.append(
                f"projection says {projection['current_state']!r}, replay says {state!r}"
            )
        if projection["custom_fields"] != fields:
            only_proj = {k: v for k, v in projection["custom_fields"].items()
                         if k not in fields or fields[k] != v}
            only_replay = {k: v for k, v in fields.items()
                           if k not in projection["custom_fields"]
                           or projection["custom_fields"][k] != v}
            drift.append(
                f"fields disagree: projection has {only_proj!r}, replay has {only_replay!r}"
            )
        last_seq = int(rows[-1]["event_seq"])
        if int(projection["last_event_seq"]) != last_seq:
            drift.append(
                f"projection's last_event_seq is {projection['last_event_seq']}, but the "
                f"final event in the history is {last_seq} (the history is truncated, "
                "or an event was written without updating the projection)"
            )
        return (state, fields, drift)
