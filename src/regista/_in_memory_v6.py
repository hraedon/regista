"""In-memory v6 epoch support — the D2 parity backend (WI-287).

``SUITE-RECONCILIATION.md`` §2.3(a) asks for "v6 parity for ``InMemoryRegista``"
under a specified boundary: a **shared semantic conformance suite** (envelope
validation, signing, sequencing, admission-state machine) over both backends,
while "locking, rollback, persistence, and concurrency/races remain
Postgres-only". The README's pin on ``InMemoryEventStore`` says the same thing
from the other side — it fails closed "until it gains an equivalent v6 genesis
implementation".

**How parity is achieved here, and why it is this way.** The strongest possible
form of "equivalent" is *the same code*, so this module does not re-implement any
v6 semantics. ``_genesis.append_v6_genesis``,
``_genesis.read_genesis_from_connection`` and ``_v6_writer.append_v6_event`` run
**unmodified** against :class:`InMemoryV6Connection`, a ``DictConn``-shaped facade
over :class:`~regista._event_store.InMemoryEventStore`'s own rows. Envelope
construction, JCS canonicalization, Ed25519 signing, §5.8 key-binding anchor
resolution, both admission gates and the sequencing/chain rules are therefore
*byte-for-byte the Postgres implementation*, executing over a different row
store. A protocol seam with two implementations was the alternative and was
rejected: it would put the semantics in two places (where they can drift, which
is exactly what a parity ticket must prevent), and it would have required editing
``_v6_writer.append_v6_event`` and ``_genesis.append_v6_genesis`` — the two
functions an in-flight sibling branch is still changing.

**The seam is therefore the storage layer, and it is a closed grammar, not an
emulator.** :class:`InMemoryV6Connection` recognises exactly the statements the v6
write and read paths issue (plus the row projections the shared conformance suite
reads back). Anything else is a named refusal listing the offending statement —
:class:`~regista._errors.ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY`. A new
statement in the Postgres path breaks the in-memory backend *loudly*, which is
the fail-closed direction: the alternative (a permissive fake) would let a
silently-diverged in-memory backend keep reporting green.

**What is deliberately NOT provided**, because ``InMemoryEventStore`` has no
machinery to fake it and a fake would launder a Postgres-gated claim:

* ``FOR UPDATE`` row locks. The facade answers the ``event_chain_head`` read the
  writer needs, but :attr:`InMemoryV6Connection.provides_transactional_isolation`
  is ``False`` and no lock is taken.
* Rollback. A transaction that raises **after** a write cannot be undone, so the
  facade refuses by name rather than leaving partial state and returning to the
  caller as though the write had been reverted. A refusal that happens *before*
  any write propagates unchanged, which is what every admission-gate test needs.
* Persistence and concurrency. Single-threaded contract, unchanged from the
  legacy in-memory store's own docstring.

``tests/test_wi287_parity_boundary.py`` enforces that split structurally rather
than trusting this docstring.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Generator, Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Final

from ._errors import ErrorCode, RegistaError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ._event_store import InMemoryEventStore

#: The events-table column order, as both v6 insert sites spell it. Used to
#: project an ``Event`` back into a row mapping.
_EVENT_COLUMNS: Final[tuple[str, ...]] = (
    "event_id",
    "work_item_id",
    "entity_kind",
    "entity_id",
    "hash_alg",
    "event_seq",
    "actor_id",
    "actor_kind",
    "actor_metadata",
    "key_id",
    "workflow_name",
    "workflow_version",
    "timestamp",
    "transition",
    "payload",
    "payload_canonical_hash",
    "signature",
    "canonical_envelope",
    "on_behalf_of",
    "scheme_id",
    "prev_event_hash",
    "global_seq",
    "prev_global_event_hash",
)

_IDENTITY_COLUMNS: Final[tuple[str, ...]] = (
    "project_instance_id",
    "trust_domain_id",
    "genesis_event_id",
    "genesis_event_hash",
    "principal_id",
    "key_id",
    "scheme_id",
    "key_fingerprint",
)

#: Relations the in-memory backend models. ``events_archive`` is deliberately
#: absent: there is no in-memory archive, and ``_genesis._archived_count``
#: already treats an absent relation as zero, so reporting it missing is the
#: truthful answer rather than a fabricated empty table.
_RELATIONS: Final[frozenset[str]] = frozenset({"events", "project_identity", "event_chain_head"})

_WS_RE = re.compile(r"\s+")
_FOR_UPDATE_RE = re.compile(r"\s+FOR\s+UPDATE$", re.IGNORECASE)
_SELECT_RE = re.compile(
    r"^SELECT\s+(?P<cols>.+?)\s+FROM\s+(?P<table>\"?[a-z_]+\"?)"
    r"(?:\s+WHERE\s+(?P<where>.+?))?"
    r"(?:\s+ORDER\s+BY\s+(?P<order>.+?))?$",
    re.IGNORECASE,
)
_TO_REGCLASS_RE = re.compile(r"^SELECT\s+to_regclass\(%s\)\s+AS\s+relation$", re.IGNORECASE)
_INSERT_RE = re.compile(
    r"^INSERT\s+INTO\s+(?P<table>[a-z_]+)\s*\((?P<cols>[^)]*)\)\s*VALUES\s*"
    r"\((?P<values>[^)]*)\)(?P<tail>.*)$",
    re.IGNORECASE,
)
_ORDER_RE = re.compile(r"^(?P<column>[a-z_]+)(?:\s+(?P<direction>ASC|DESC))?$", re.IGNORECASE)
_COUNT_RE = re.compile(r"^COUNT\(\*\)\s+AS\s+(?P<alias>[a-z_]+)$", re.IGNORECASE)
_NEXT_SEQ_RE = re.compile(
    r"^COALESCE\(MAX\((?P<column>[a-z_]+)\),\s*0\)\s*\+\s*1\s+AS\s+(?P<alias>[a-z_]+)$",
    re.IGNORECASE,
)
_ATOM_PARAM_RE = re.compile(r"^(?P<column>[a-z_]+)\s*=\s*%s$", re.IGNORECASE)
_ATOM_ANY_RE = re.compile(r"^(?P<column>[a-z_]+)\s*=\s*ANY\(%s\)$", re.IGNORECASE)
_ATOM_TRUE_RE = re.compile(r"^(?P<column>[a-z_]+)\s*=\s*TRUE$", re.IGNORECASE)
_ATOM_LITERAL_RE = re.compile(r"^(?P<column>[a-z_]+)\s*=\s*'(?P<value>[^']*)'$", re.IGNORECASE)


def _refuse(statement: str, reason: str) -> RegistaError:
    return RegistaError(
        ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY,
        f"the in-memory v6 backend does not implement this statement: {reason}. "
        "SUITE-RECONCILIATION.md §2.3(a) keeps locking, rollback, persistence and "
        "concurrency Postgres-only, and every other statement must be added to the "
        "closed grammar in _in_memory_v6.py deliberately rather than faked.",
        detail={"statement": statement, "reason": reason},
    )


def _normalize(query: object) -> str:
    """Render a psycopg ``SQL``/``Composed``/``str`` query to comparable text."""

    if isinstance(query, str):
        text = query
    elif isinstance(query, bytes):
        text = query.decode("utf-8")
    else:
        as_string = getattr(query, "as_string", None)
        if as_string is None:
            raise _refuse(repr(query), "unrenderable query object")
        text = as_string(None)
    return _WS_RE.sub(" ", text).strip().rstrip(";")


def _unwrap(value: object) -> Any:
    """Strip a ``psycopg.types.json.Jsonb`` wrapper; leave everything else alone.

    The type name is checked *before* reading ``.obj`` on purpose: testing
    ``obj is not None`` first would silently pass a ``Jsonb(None)`` through as the
    wrapper object, and the stored ``payload`` would then be a psycopg adapter
    instead of ``None`` — wrong, and invisible until something serialised it.
    """

    if type(value).__name__ in {"Jsonb", "Json"}:
        return getattr(value, "obj", value)
    return value


class _Result:
    """The ``fetchone``/``fetchall`` surface ``conn.execute(...)`` returns."""

    __slots__ = ("_rows",)

    def __init__(self, rows: Sequence[dict[str, Any]]) -> None:
        self._rows = list(rows)

    def fetchone(self) -> dict[str, Any] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[dict[str, Any]]:
        return list(self._rows)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self._rows)


class InMemoryV6Rows:
    """The v6 relations, held beside ``InMemoryEventStore``'s event list.

    Deliberately not a second event store: ``events`` reads project straight out
    of the one ``InMemoryEventStore`` the backend already uses, so an event
    written through the v6 path is visible to ``read_events`` and to every
    projection without a sync step. Only the two relations the legacy in-memory
    store never had — ``project_identity`` and ``event_chain_head`` — are stored
    here.
    """

    def __init__(self, store: InMemoryEventStore) -> None:
        self.store = store
        self.project_identity: dict[str, Any] | None = None
        self.head_event_id: uuid.UUID | None = None

    @property
    def head_hash(self) -> bytes | None:
        """The global chain head — the store's ``_global_chain_head``, not a copy.

        Postgres has exactly **one** ``event_chain_head`` row: the writer advances it
        (``_events._advance_global_chain_head``) and replay reads it back to check the
        head against the chain tail. In memory there were two: this relation, which the
        v6 writer advanced through the facade, and ``InMemoryEventStore._global_chain_head``,
        which only the *legacy* ``append`` ever wrote — and which is the one
        ``_in_memory_replay`` reads. So after a v6 epoch the head replay consulted was
        still ``None``, and WI-266's fail-closed check for "head set, log empty" — the
        signature of a wholesale-deleted log — was **unreachable in memory** while
        Postgres detected it correctly. A fail-open gap of exactly the class WI-266
        closed, and the second hole measured in WI-287's parity claim after finding 16.

        The fix is the parity discipline rather than a second advance: two pieces of
        state that must agree are one piece of state. Nothing is copied and nothing is
        synchronised, so there is no window in which they disagree, and the v6 and
        legacy appenders cannot fork the head (they are mutually exclusive anyway —
        ``_genesis.check_legacy_append`` refuses a legacy append on both sides of
        genesis). Note this is deliberately NOT an advance inside
        ``append_v6_row``: on Postgres the *writer* advances the head, explicitly,
        after the insert, and the in-memory path must be the same shape or it is a
        different mechanism wearing the same name.
        """

        return self.store._global_chain_head

    @head_hash.setter
    def head_hash(self, value: bytes | None) -> None:
        self.store._global_chain_head = value

    # -- events ------------------------------------------------------------
    def event_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for event in self.store.all_events():
            rows.append(
                {
                    "event_id": event.event_id,
                    "work_item_id": event.work_item_id,
                    "entity_kind": event.entity_kind,
                    "entity_id": event.effective_entity_id,
                    "hash_alg": event.hash_alg,
                    "event_seq": event.event_seq,
                    "actor_id": event.actor_id,
                    "actor_kind": event.actor_kind,
                    "actor_metadata": event.actor_metadata,
                    "key_id": event.key_id,
                    "workflow_name": event.workflow_name,
                    "workflow_version": event.workflow_version,
                    "timestamp": event.timestamp,
                    "transition": event.transition,
                    "payload": event.payload,
                    "payload_canonical_hash": event.payload_canonical_hash,
                    "signature": event.signature,
                    "canonical_envelope": event.canonical_envelope,
                    "on_behalf_of": event.on_behalf_of,
                    "scheme_id": event.scheme_id,
                    "prev_event_hash": event.prev_event_hash,
                    "global_seq": event.global_seq,
                    "prev_global_event_hash": event.prev_global_event_hash,
                }
            )
        rows.sort(key=lambda row: (row["global_seq"] is None, row["global_seq"] or 0))
        return rows

    def identity_rows(self) -> list[dict[str, Any]]:
        if self.project_identity is None:
            return []
        # ``id`` carries the Postgres singleton primary key so ``WHERE id = TRUE``
        # selects the row rather than silently matching nothing.
        return [{"id": True, **self.project_identity}]

    def chain_head_rows(self) -> list[dict[str, Any]]:
        # The sentinel row always exists (migration 035's shape): head_hash is
        # NULL until the first event lands, which is exactly what
        # _events._lock_global_chain_head reads to decide "genesis".
        return [{"id": True, "head_hash": self.head_hash, "head_event_id": self.head_event_id}]


class InMemoryV6Connection:
    """A ``DictConn``-shaped facade over :class:`InMemoryV6Rows`.

    Only :meth:`execute` is offered, because only :meth:`execute` is what the v6
    write and read paths use. ``commit``/``rollback``/``transaction`` are
    intentionally absent: a caller reaching for them is reaching for the
    Postgres-only half of §2.3(a) and should fail with ``AttributeError`` at the
    call site rather than be handed a silent no-op.
    """

    #: The parity boundary, as a machine-readable fact rather than a comment.
    #: Anything that needs true isolation must consult this and refuse.
    provides_transactional_isolation: Final[bool] = False

    def __init__(self, rows: InMemoryV6Rows, *, read_only: bool = False) -> None:
        self._rows = rows
        self._read_only = read_only
        self.writes = 0

    # -- entry point -------------------------------------------------------
    def execute(self, query: object, params: Sequence[Any] | None = None) -> _Result:
        text = _normalize(query)
        values = [_unwrap(p) for p in (params or [])]

        regclass = _TO_REGCLASS_RE.match(text)
        if regclass is not None:
            name = str(values[0]) if values else ""
            return _Result([{"relation": name if name in _RELATIONS else None}])

        upper = text.upper()
        if upper.startswith("SELECT"):
            return self._select(text, values)
        if upper.startswith("INSERT"):
            return self._insert(text, values)
        raise _refuse(text, "only SELECT and INSERT are modelled")

    # -- SELECT ------------------------------------------------------------
    def _select(self, text: str, values: list[Any]) -> _Result:
        body = _FOR_UPDATE_RE.sub("", text)
        # A FOR UPDATE that reached here is answered as a plain read. That is the
        # honest in-memory behaviour and is why provides_transactional_isolation
        # is False; the structural guard asserts no shared conformance test
        # depends on the lock.
        match = _SELECT_RE.match(body)
        if match is None:
            raise _refuse(text, "unparsable SELECT")
        table = match.group("table").strip('"').lower()
        if table == "events":
            rows = self._rows.event_rows()
        elif table == "project_identity":
            rows = self._rows.identity_rows()
        elif table == "event_chain_head":
            rows = self._rows.chain_head_rows()
        else:
            raise _refuse(text, f"relation {table!r} is not modelled in memory")

        where = match.group("where")
        if where:
            rows = self._filter(text, rows, where, values)
        order = match.group("order")
        if order:
            rows = self._order(text, rows, order)
        return _Result(self._project(text, rows, match.group("cols")))

    def _filter(
        self, text: str, rows: list[dict[str, Any]], where: str, values: list[Any]
    ) -> list[dict[str, Any]]:
        cursor = 0
        for atom in re.split(r"\s+AND\s+", where, flags=re.IGNORECASE):
            atom = atom.strip()
            param = _ATOM_PARAM_RE.match(atom)
            if param is not None:
                if cursor >= len(values):
                    raise _refuse(text, "more %s placeholders than parameters")
                wanted = values[cursor]
                cursor += 1
                column = param.group("column").lower()
                rows = [r for r in rows if self._compare(text, column, r.get(column), wanted)]
                continue
            member = _ATOM_ANY_RE.match(atom)
            if member is not None:
                if cursor >= len(values):
                    raise _refuse(text, "more %s placeholders than parameters")
                wanted_any = values[cursor]
                cursor += 1
                column = member.group("column").lower()
                rows = [
                    r
                    for r in rows
                    if any(self._compare(text, column, r.get(column), w) for w in wanted_any)
                ]
                continue
            truthy = _ATOM_TRUE_RE.match(atom)
            if truthy is not None:
                column = truthy.group("column").lower()
                rows = [r for r in rows if r.get(column) is True]
                continue
            literal = _ATOM_LITERAL_RE.match(atom)
            if literal is not None:
                column = literal.group("column").lower()
                wanted_text = literal.group("value")
                rows = [
                    r for r in rows if self._compare(text, column, r.get(column), wanted_text)
                ]
                continue
            raise _refuse(text, f"unmodelled WHERE atom {atom!r}")
        return rows

    @staticmethod
    def _compare(text: str, column: str, left: Any, right: Any) -> bool:
        """``column = value`` for a modelled statement, refusing on NULL.

        See :func:`_refuse_null_comparison`: ``NULL = NULL`` is NULL in Postgres and
        was ``True`` here, so this is a refusal rather than a coercion.
        """

        if left is None or right is None:
            raise _refuse_null_comparison(text, column, "an equality comparison")
        return _same(left, right)

    def _order(self, text: str, rows: list[dict[str, Any]], order: str) -> list[dict[str, Any]]:
        for clause in reversed([c.strip() for c in order.split(",")]):
            spec = _ORDER_RE.match(clause)
            if spec is None:
                raise _refuse(text, f"unmodelled ORDER BY clause {clause!r}")
            column = spec.group("column").lower()
            descending = (spec.group("direction") or "ASC").upper() == "DESC"
            if any(row.get(column) is None for row in rows):
                # NULLS LAST for ASC and NULLS FIRST for DESC is Postgres's default,
                # and `or 0` delivered neither (it also flattened 0/""/False). Refused
                # rather than modelled — see _refuse_null_comparison.
                raise _refuse_null_comparison(text, column, "an ORDER BY")
            rows = sorted(
                rows,
                key=lambda row: row[column],
                reverse=descending,
            )
        return rows

    def _project(
        self, text: str, rows: list[dict[str, Any]], cols: str
    ) -> list[dict[str, Any]]:
        selectors = [c.strip() for c in _split_top_level(cols)]
        if len(selectors) == 1:
            counted = _COUNT_RE.match(selectors[0])
            if counted is not None:
                return [{counted.group("alias").lower(): len(rows)}]
            next_seq = _NEXT_SEQ_RE.match(selectors[0])
            if next_seq is not None:
                column = next_seq.group("column").lower()
                seen = [int(r[column]) for r in rows if r.get(column) is not None]
                return [{next_seq.group("alias").lower(): (max(seen) if seen else 0) + 1}]
        out: list[dict[str, Any]] = []
        for row in rows:
            projected: dict[str, Any] = {}
            for selector in selectors:
                column = selector.lower()
                if column not in row:
                    raise _refuse(text, f"unmodelled selected column {selector!r}")
                projected[column] = row[column]
            out.append(projected)
        return out

    # -- INSERT ------------------------------------------------------------
    def _insert(self, text: str, values: list[Any]) -> _Result:
        if self._read_only:
            raise RegistaError(
                ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY,
                "this in-memory v6 connection is read-only; a write through it "
                "would silently escape the read-only contract the Postgres path "
                "gets from SET TRANSACTION READ ONLY",
                detail={"statement": text},
            )
        match = _INSERT_RE.match(text)
        if match is None:
            raise _refuse(text, "unparsable INSERT")
        table = match.group("table").lower()
        columns = [c.strip().lower() for c in match.group("cols").split(",")]
        slots = [v.strip() for v in match.group("values").split(",")]
        if len(columns) != len(slots):
            raise _refuse(text, "column/value arity mismatch")

        assigned: dict[str, Any] = {}
        cursor = 0
        for column, slot in zip(columns, slots, strict=True):
            if slot == "%s":
                if cursor >= len(values):
                    raise _refuse(text, "more %s placeholders than parameters")
                assigned[column] = values[cursor]
                cursor += 1
            elif slot.upper() == "TRUE":
                assigned[column] = True
            elif slot.upper() == "FALSE":
                assigned[column] = False
            elif slot.upper() == "EXCLUDED.HEAD_HASH":  # pragma: no cover - defensive
                raise _refuse(text, "ON CONFLICT projections are not modelled in VALUES")
            else:
                raise _refuse(text, f"unmodelled VALUES entry {slot!r}")
        self.writes += 1

        if table == "events":
            return _Result([{"global_seq": self._insert_event(text, assigned)}])
        if table == "project_identity":
            if self._rows.project_identity is not None:
                raise RegistaError(
                    ErrorCode.GENESIS_ALREADY_WRITTEN,
                    "project_identity already holds a genesis binding; the "
                    "in-memory singleton mirrors the Postgres primary key",
                )
            self._rows.project_identity = {
                column: assigned.get(column) for column in _IDENTITY_COLUMNS
            }
            return _Result([])
        if table == "event_chain_head":
            self._rows.head_hash = assigned.get("head_hash")
            head_event = assigned.get("head_event_id")
            self._rows.head_event_id = (
                head_event if head_event is None else uuid.UUID(str(head_event))
            )
            return _Result([])
        raise _refuse(text, f"relation {table!r} is not modelled in memory")

    def _insert_event(self, text: str, assigned: Mapping[str, Any]) -> int:
        from ._types import Event

        missing = [c for c in _EVENT_COLUMNS if c not in assigned and c != "global_seq"]
        if missing:
            raise _refuse(text, f"events insert omits modelled columns {missing}")
        entity_id = assigned["entity_id"]
        event = Event(
            event_id=_as_uuid(assigned["event_id"]),
            work_item_id=_as_uuid(assigned["work_item_id"]),
            entity_kind=str(assigned["entity_kind"]),
            entity_id=None if entity_id is None else _as_uuid(entity_id),
            hash_alg=str(assigned["hash_alg"]),
            event_seq=int(assigned["event_seq"]),
            actor_id=str(assigned["actor_id"]),
            actor_kind=str(assigned["actor_kind"]),
            actor_metadata=assigned["actor_metadata"],
            key_id=str(assigned["key_id"]),
            workflow_name=assigned["workflow_name"],
            workflow_version=assigned["workflow_version"],
            timestamp=assigned["timestamp"],
            transition=assigned["transition"],
            payload=assigned["payload"],
            payload_canonical_hash=_as_bytes(assigned["payload_canonical_hash"]),
            signature=_as_bytes(assigned["signature"]),
            canonical_envelope=_as_optional_bytes(assigned["canonical_envelope"]),
            on_behalf_of=assigned["on_behalf_of"],
            scheme_id=str(assigned["scheme_id"]),
            prev_event_hash=_as_optional_bytes(assigned["prev_event_hash"]),
            prev_global_event_hash=_as_optional_bytes(assigned["prev_global_event_hash"]),
        )
        return self._rows.store.append_v6_row(event)


def _as_uuid(value: Any) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _as_bytes(value: Any) -> bytes:
    return bytes(value)


def _as_optional_bytes(value: Any) -> bytes | None:
    return None if value is None else bytes(value)


def _refuse_null_comparison(text: str, column: str, what: str) -> RegistaError:
    """A modelled statement touched NULL, where this facade would have to guess.

    Postgres three-valued logic and this facade's Python semantics differ in exactly
    two places, and both were latent (no statement in the closed grammar reaches them
    today — the phase-4 ceremony's NB4 found them by reading):

    * ``_same(None, None)`` returned ``True``. In SQL ``NULL = NULL`` is NULL, so the
      row does **not** match. A facade that answers ``TRUE`` there makes an in-memory
      pass mean something the Postgres path would not.
    * ``ORDER BY`` sorted NULLs last in both directions, via ``row.get(column) or 0``.
      Postgres defaults to NULLS LAST for ASC and NULLS **FIRST** for DESC, and the
      ``or 0`` additionally flattens ``0``/``""``/``False`` into the same key.

    Rather than model either — modelling is how a facade grows into a second database
    with its own bugs — the statement is refused by name, exactly as an unmodelled
    relation or WHERE atom is. A future statement that legitimately needs NULL
    semantics therefore fails loudly at its own call site and gets added to the
    grammar deliberately, instead of quietly returning a different answer than
    production.
    """

    return _refuse(
        text,
        f"{what} on column {column!r} touches NULL, and SQL's three-valued logic is "
        "not modelled in memory",
    )


def _same(left: Any, right: Any) -> bool:
    """Equality with the coercions a real column comparison would perform.

    NULL-free by contract: callers inside a modelled statement must route through
    :meth:`InMemoryV6Connection._compare`, which refuses first. This retains the
    ``left is right`` answer only so a direct caller outside statement handling is not
    handed a crash.
    """

    if left is None or right is None:
        return left is right
    if isinstance(left, uuid.UUID) or isinstance(right, uuid.UUID):
        return str(left) == str(right)
    if isinstance(left, (bytes, bytearray, memoryview)) and isinstance(
        right, (bytes, bytearray, memoryview)
    ):
        return bytes(left) == bytes(right)
    if isinstance(left, bool) or isinstance(right, bool):
        return left is right
    return bool(left == right)


def _split_top_level(text: str) -> list[str]:
    """Split a select list on commas that are not inside parentheses."""

    parts: list[str] = []
    depth = 0
    current: list[str] = []
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return [p for p in (part.strip() for part in parts) if p]


class InMemoryV6ConnectionManager:
    """The ``_mgr`` surface, so the shared conformance suite reads one way.

    ``transaction()`` yields the facade and **does not** roll back: a write that
    has happened cannot be undone in memory. When an exception escapes a
    transaction that already wrote, the failure is re-raised wrapped in a named
    refusal rather than returning to the caller as though the write had been
    reverted — a silent partial commit is exactly the shape §2.3(a) refuses to
    let an in-memory backend pretend away. A refusal raised *before* any write
    propagates untouched, which is what the admission-gate assertions need.
    """

    def __init__(self, rows: InMemoryV6Rows) -> None:
        self._rows = rows

    @contextmanager
    def transaction(self) -> Generator[InMemoryV6Connection, None, None]:
        conn = InMemoryV6Connection(self._rows)
        try:
            yield conn
        except Exception as exc:
            if conn.writes:
                raise RegistaError(
                    ErrorCode.PARITY_BOUNDARY_POSTGRES_ONLY,
                    "an in-memory v6 transaction failed after writing and cannot "
                    "roll back; rollback is Postgres-only "
                    "(SUITE-RECONCILIATION.md §2.3(a)) and a silent partial commit "
                    f"is refused instead of faked. Original failure: {exc!r}",
                    detail={"writes": conn.writes, "original": repr(exc)},
                ) from exc
            raise

    @contextmanager
    def read_only_transaction(self) -> Generator[InMemoryV6Connection, None, None]:
        yield InMemoryV6Connection(self._rows, read_only=True)


__all__ = [
    "InMemoryV6Connection",
    "InMemoryV6ConnectionManager",
    "InMemoryV6Rows",
]
