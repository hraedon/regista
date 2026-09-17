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
  * Lease expiry is decided by the DATABASE clock, never the caller's. A
    coordination store has many clients and one serialization point; if the
    writer's clock decided liveness while queries used now(), available() and
    transition() could disagree about whether a lease is still held.
  * A lease stops a stale worker committing to THIS store. It does not stop that
    process making external requests. Fencing external effects is the caller's
    job -- pass `attempt` to the target system too.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.rows import DictRow, dict_row
from psycopg.types.json import Jsonb

DictConn = psycopg.Connection[DictRow]
DictCursor = psycopg.Cursor[DictRow]

KERNEL_SCHEMA_VERSION = 1


class KernelError(Exception):
    """Base class. Every refusal below is one of these, never a bare psycopg error."""


class UnsupportedSchemaError(KernelError): ...
class InvalidWorkflowError(KernelError): ...
class TransitionRefusedError(KernelError): ...
class ClaimContestedError(KernelError): ...
class StaleAttemptError(KernelError): ...
class InvalidFieldError(KernelError): ...
class IdempotencyConflictError(KernelError): ...


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _canonical(obj: object) -> bytes:
    """Deterministic JSON bytes. Sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


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
        return cls(conn, schema)

    def close(self) -> None:
        self._conn.close()

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
                (wf.name, version, Jsonb(body), content_hash),
            )
        self._conn.commit()
        return version

    def get_workflow(self, name: str, version: int | None = None) -> Workflow:
        with self._conn.cursor() as cur:
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
            raise InvalidWorkflowError(f"no such workflow: {name} v{version}")
        return Workflow.from_json(row["definition"], int(row["version"]))

    def list_workflows(self) -> list[tuple[str, int, datetime]]:
        """Every registered workflow version, oldest first."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT workflow_name, version, registered_at FROM workflow_registry "
                "ORDER BY workflow_name, version"
            )
            rows = cur.fetchall()
        self._conn.commit()
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
                ("live_leases", "SELECT count(*) AS n FROM claims WHERE expires_at > now()"),
                ("events", "SELECT count(*) AS n FROM events"),
                ("workflows", "SELECT count(*) AS n FROM workflow_registry"),
            ):
                cur.execute(sql)
                r = cur.fetchone()
                counts[label] = int(r["n"]) if r else 0
        self._conn.commit()
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
        wf = self.get_workflow(workflow, workflow_version)
        fields = dict(fields or {})
        item_id = uuid.uuid4()
        now = _utcnow()
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO work_items_current (work_item_id, workflow_name, workflow_version, "
                "work_item_type, current_state, custom_fields, last_event_seq, next_event_seq, "
                "last_event_at) VALUES (%s, %s, %s, %s, %s, %s, 0, 1, %s)",
                (item_id, wf.name, wf.version, type, wf.initial, Jsonb(fields), now),
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
        if not row:
            raise KernelError(f"no such work item: {work_item_id}")
        return WorkItem(
            row["work_item_id"], row["workflow_name"], row["workflow_version"],
            row["work_item_type"], row["current_state"], row["custom_fields"],
            row["last_event_seq"],
        )

    # ---- claims ----------------------------------------------------------

    def claim(self, work_item_id: uuid.UUID, *, actor_id: str, ttl_seconds: int = 300) -> Claim:
        """Acquire a lease, taking over an expired one. Refuses a live foreign lease."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT work_item_id FROM work_items_current WHERE work_item_id = %s FOR UPDATE",
                (work_item_id,),
            )
            if not cur.fetchone():
                self._conn.rollback()
                raise KernelError(f"no such work item: {work_item_id}")
            cur.execute(
                "SELECT actor_id, expires_at, expires_at > now() AS live "
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
                "VALUES (%s, %s, %s, now(), now() + make_interval(secs => %s)) "
                "ON CONFLICT (work_item_id) DO UPDATE SET actor_id = EXCLUDED.actor_id, "
                "attempt_number = EXCLUDED.attempt_number, acquired_at = EXCLUDED.acquired_at, "
                "expires_at = EXCLUDED.expires_at "
                "RETURNING expires_at",
                (work_item_id, actor_id, attempt, ttl_seconds),
            )
            claim_row = cur.fetchone()
            if claim_row is None:  # pragma: no cover - RETURNING always yields a row here
                self._conn.rollback()
                raise KernelError(f"failed to record the lease for {work_item_id}")
            expires = claim_row["expires_at"]
        self._conn.commit()
        return Claim(work_item_id, actor_id, attempt, expires)

    def heartbeat(self, claim: Claim, *, ttl_seconds: int = 300) -> Claim:
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE claims SET expires_at = now() + make_interval(secs => %s) "
                "WHERE work_item_id = %s AND actor_id = %s AND attempt_number = %s "
                "RETURNING expires_at",
                (ttl_seconds, claim.work_item_id, claim.actor_id, claim.attempt),
            )
            row = cur.fetchone()
            if not row:
                self._conn.rollback()
                raise StaleAttemptError(
                    f"attempt {claim.attempt} for {claim.work_item_id} is no longer the "
                    "current lease; it expired and was taken over"
                )
            expires = row["expires_at"]
        self._conn.commit()
        return Claim(claim.work_item_id, claim.actor_id, claim.attempt, expires)

    def release(self, work_item_id: uuid.UUID, *, actor_id: str, attempt: int) -> None:
        """Release a lease. Takes the primitive rather than a Claim, so a CLI
        holding only (id, actor, attempt) can call it without fabricating one."""
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
            cur.execute("DELETE FROM claims WHERE expires_at <= now()")
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

        `attempt` is the fencing token from claim(). If the item is under a live
        lease, a caller must supply the CURRENT attempt or be refused -- that is
        what makes a stale worker harmless to this store.
        """
        request_hash = _hash(_canonical({
            "w": str(work_item_id), "t": transition, "a": actor_id,
            "f": fields or {}, "p": payload or {},
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

            wf = self.get_workflow(item["workflow_name"], item["workflow_version"])

            # Lease fencing, before any validation that could leak state.
            cur.execute(
                "SELECT actor_id, attempt_number, expires_at > now() AS live "
                "FROM claims WHERE work_item_id = %s",
                (work_item_id,),
            )
            lease = cur.fetchone()
            if lease and lease["live"]:
                if attempt is None:
                    self._conn.rollback()
                    raise StaleAttemptError(
                        f"work item {work_item_id} is under a live lease (attempt "
                        f"{lease['attempt_number']}); lease-protected writes must pass attempt="
                    )
                if int(attempt) != int(lease["attempt_number"]):
                    self._conn.rollback()
                    raise StaleAttemptError(
                        f"attempt {attempt} is stale: the current lease on {work_item_id} is "
                        f"attempt {lease['attempt_number']}, held by {lease['actor_id']!r}. "
                        "Refusing the write."
                    )

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
                self._conn.rollback()
                raise TransitionRefusedError(
                    f"{transition!r} leaves {sorted(froms)}, but the item is in {state!r}"
                )
            allowed = wf.roles.get(transition)
            if allowed and (role is None or role not in allowed):
                self._conn.rollback()
                raise TransitionRefusedError(
                    f"{transition!r} is restricted to roles {sorted(allowed)}; "
                    f"caller presented {role!r}"
                )

            merged = dict(item["custom_fields"])
            merged.update(fields or {})
            missing = [f for f in wf.required_fields.get(transition, ()) if f not in merged]
            if missing:
                self._conn.rollback()
                raise InvalidFieldError(
                    f"{transition!r} requires field(s) {missing} to be set on the item"
                )

            seq = int(item["next_event_seq"])
            now = _utcnow()
            event_id = self._append_event(
                cur, work_item_id, seq=seq, actor_id=actor_id, actor_kind=actor_kind,
                transition=transition,
                payload={"from": state, "to": to, "fields": fields or {}, **(payload or {})},
                occurred_at=now,
            )
            cur.execute(
                "UPDATE work_items_current SET current_state = %s, custom_fields = %s, "
                "last_event_seq = %s, next_event_seq = %s, last_event_at = %s "
                "WHERE work_item_id = %s",
                (to, Jsonb(merged), seq, seq + 1, now, work_item_id),
            )
            if idempotency_key is not None:
                cur.execute(
                    "INSERT INTO idempotency_keys (idempotency_key, work_item_id, event_id, "
                    "request_hash) VALUES (%s, %s, %s, %s)",
                    (idempotency_key, work_item_id, event_id, request_hash),
                )
        self._conn.commit()
        return self.get(work_item_id)

    def _append_event(
        self, cur: DictCursor, work_item_id: uuid.UUID, *, seq: int, actor_id: str,
        actor_kind: str, transition: str | None, payload: dict[str, Any],
        occurred_at: datetime,
    ) -> uuid.UUID:
        """Append one event, chained to its predecessor for CONSISTENCY only."""
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
             Jsonb(payload), payload_hash, prev_hash, occurred_at),
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
            return [(r["target_id"], r["link_type"]) for r in cur.fetchall()]

    # ---- discovery queries ----------------------------------------------

    def available(self, *, workflow: str | None = None, states: tuple[str, ...] = (),
                  limit: int = 50) -> list[WorkItem]:
        """Items in the given states with no live lease. Ordered oldest-first."""
        sql = [
            "SELECT w.* FROM work_items_current w",
            "LEFT JOIN claims c ON c.work_item_id = w.work_item_id AND c.expires_at > now()",
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
            "WHERE c.actor_id = %s AND c.expires_at > now() "
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
        self._conn.commit()
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
        self._conn.commit()
        return [
            Event(r["event_seq"], r["actor_id"], r["actor_kind"], r["transition"],
                  r["payload"], r["occurred_at"])
            for r in rows
        ]

    def replay(self, work_item_id: uuid.UUID) -> tuple[str, dict[str, Any], list[str]]:
        """Rebuild state from events alone. Returns (state, fields, drift).

        Drift is reported honestly rather than raised: replay's job is to say
        what the history supports and where it disagrees with the projection.
        """
        events = self.history(work_item_id)
        drift: list[str] = []
        if not events:
            return ("", {}, ["no events"])

        state: str = ""
        fields: dict[str, Any] = {}
        for i, e in enumerate(events):
            if e.seq != i:
                drift.append(f"sequence gap: expected {i}, found {e.seq}")
            if e.transition is None:
                created = e.payload.get("created", {})
                state = created.get("state", "")
                fields = dict(created.get("fields", {}))
            else:
                if e.payload.get("from") != state:
                    drift.append(
                        f"event {e.seq} leaves {e.payload.get('from')!r} "
                        f"but replay is in {state!r}"
                    )
                state = e.payload.get("to", state)
                fields.update(e.payload.get("fields", {}))

        # Chain check. Consistency only -- see the module docstring.
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT event_seq, payload, payload_hash, prev_event_hash FROM events "
                "WHERE work_item_id = %s ORDER BY event_seq",
                (work_item_id,),
            )
            rows = cur.fetchall()
        self._conn.commit()
        running = None
        for r in rows:
            if bytes(r["payload_hash"]) != _hash(_canonical(r["payload"])):
                drift.append(f"event {r['event_seq']}: payload does not match its hash")
            stored = bytes(r["prev_event_hash"]) if r["prev_event_hash"] is not None else None
            if stored != running:
                drift.append(f"event {r['event_seq']}: chain link does not match predecessor")
            running = _hash(bytes(r["payload_hash"]), bytes(stored or b""))

        current = self.get(work_item_id)
        if current.state != state:
            drift.append(f"projection says {current.state!r}, replay says {state!r}")
        return (state, fields, drift)
