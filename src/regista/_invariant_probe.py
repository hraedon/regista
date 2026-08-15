from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import psycopg
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

from ._connection import validate_project_name
from ._contract import validate_actor_metadata, validate_delegation_chain
from ._errors import ErrorCode, RegistaError
from ._genesis import first_write_admission, validate_load_bearing_fields
from ._lineage import MODEL_LINEAGE_FAMILIES


@dataclass(frozen=True)
class ProjectInvariantMeasurements:
    project: str
    event_count: int
    declared_lineage_event_count: int
    distinct_lineage_tokens: tuple[str, ...]
    unresolvable_lineage_tokens: tuple[str, ...]
    unresolvable_lineage_value_count: int
    ambiguous_lineage_event_count: int
    scheme_counts: dict[str, int]
    undeclared_agent_author_event_count: int
    model_observation_status_counts: dict[str, int]
    snapshot_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "event_count": self.event_count,
            "declared_lineage_event_count": self.declared_lineage_event_count,
            "lineage_coverage": {
                "numerator": self.declared_lineage_event_count,
                "denominator": self.event_count,
            },
            "distinct_lineage_tokens": list(self.distinct_lineage_tokens),
            "unresolvable_lineage_tokens": list(self.unresolvable_lineage_tokens),
            "unresolvable_lineage_value_count": self.unresolvable_lineage_value_count,
            "ambiguous_lineage_event_count": self.ambiguous_lineage_event_count,
            "scheme_counts": dict(sorted(self.scheme_counts.items())),
            "undeclared_agent_author_event_count": self.undeclared_agent_author_event_count,
            "model_observation_status_counts": dict(
                sorted(self.model_observation_status_counts.items())
            ),
            "snapshot_id": self.snapshot_id,
        }


def _delegation_lineages(value: object) -> Iterable[tuple[object, bool]]:
    current = value
    depth = 0
    while isinstance(current, dict) and depth < 16:
        principal_kind = current.get("principal_kind")
        is_agent = (
            isinstance(principal_kind, str)
            and principal_kind.strip().lower() == "agent"
        )
        yield current.get("principal_lineage"), is_agent
        current = current.get("on_behalf_of")
        depth += 1


#: Row keys carrying the v6 producer lineage already extracted by the query.
#: ``probe_project`` projects these server-side so the measurement never ships
#: whole ``canonical_envelope`` blobs over the wire; rows that arrive with a
#: raw envelope instead (unit tests, callers holding rows in hand) are parsed
#: here exactly as before. The two paths must agree — see
#: ``test_projected_and_raw_envelope_rows_measure_identically``.
ENVELOPE_PRODUCER_PRESENT_KEY = "envelope_producer_present"
ENVELOPE_LINEAGE_KEY = "envelope_model_lineage"


def _envelope_producer_lineage(row: dict[str, Any]) -> tuple[bool, object]:
    """Return ``(producer_present, model_lineage)`` for a v6 envelope.

    ``producer_present`` is true only when the envelope parses as a JSON object
    declaring ``version == 6`` whose ``producer`` is itself an object. Anything
    else — absent envelope, undecodable bytes, a different version, a producer
    that is not an object — reads as absent, and the caller falls through to the
    payload and actor-metadata sources.
    """
    if ENVELOPE_PRODUCER_PRESENT_KEY in row:
        return bool(row.get(ENVELOPE_PRODUCER_PRESENT_KEY)), row.get(ENVELOPE_LINEAGE_KEY)
    envelope = row.get("canonical_envelope")
    if envelope is None:
        return False, None
    try:
        parsed = json.loads(bytes(envelope))
    except (TypeError, ValueError, UnicodeDecodeError):
        return False, None
    if not (isinstance(parsed, dict) and parsed.get("version") == 6):
        return False, None
    producer = parsed.get("producer")
    if not isinstance(producer, dict):
        return False, None
    return True, producer.get("model_lineage")


def _event_lineages(row: dict[str, Any]) -> list[tuple[object, bool]]:
    result: list[tuple[object, bool]] = []
    actor_kind = row.get("actor_kind")
    actor_is_agent = isinstance(actor_kind, str) and actor_kind.strip().lower() == "agent"
    producer_present, producer_lineage = _envelope_producer_lineage(row)
    if producer_present:
        result.append((producer_lineage, actor_is_agent))
    # Ordering seam, latent until v6 envelopes carry a producer block: a
    # model_observation event is written by cairn, whose actor declares no
    # model_lineage of its own, so today the payload's observed lineage is what
    # gets measured. Once producer_present starts coming back true for these
    # rows, the branch below stops running and they will read as undeclared
    # agent authors instead. Settling that means deciding whose lineage a
    # model_observation event carries — the observer's or the observed's — which
    # is a modelling question, not a measurement one.
    if not result and row.get("transition") == "model_observation":
        payload = row.get("payload")
        observed_lineage = (
            payload.get("observed_model_lineage") if isinstance(payload, dict) else None
        )
        result.append((observed_lineage, actor_is_agent))
    if not result:
        metadata = row.get("actor_metadata")
        lineage = metadata.get("model_lineage") if isinstance(metadata, dict) else None
        result.append((lineage, actor_is_agent))
    result.extend(_delegation_lineages(row.get("on_behalf_of")))
    return result


def measure_event_rows(
    project: str,
    rows: Iterable[dict[str, Any]],
    *,
    snapshot_id: str = "",
) -> ProjectInvariantMeasurements:
    event_count = 0
    declared_lineage_event_count = 0
    distinct_tokens: set[str] = set()
    unresolvable_tokens: set[str] = set()
    unresolvable_value_count = 0
    ambiguous_lineage_event_count = 0
    scheme_counts: dict[str, int] = {}
    undeclared_agent_author_event_count = 0
    model_observation_status_counts: dict[str, int] = {}

    for row in rows:
        event_count += 1
        raw_lineages = _event_lineages(row)
        valid_lineages: set[str] = set()
        agent_lineages: list[object] = []
        for raw, is_agent in raw_lineages:
            if is_agent:
                agent_lineages.append(raw)
            if raw is None:
                continue
            if isinstance(raw, str):
                distinct_tokens.add(raw)
                if raw in MODEL_LINEAGE_FAMILIES:
                    valid_lineages.add(raw)
                else:
                    unresolvable_tokens.add(raw)
            else:
                unresolvable_value_count += 1
        if valid_lineages:
            declared_lineage_event_count += 1
        if len(valid_lineages) > 1:
            ambiguous_lineage_event_count += 1
        if agent_lineages and any(
            not isinstance(raw, str) or raw not in MODEL_LINEAGE_FAMILIES
            for raw in agent_lineages
        ):
            undeclared_agent_author_event_count += 1

        scheme = row.get("scheme_id")
        scheme_key = scheme if isinstance(scheme, str) and scheme else "unknown"
        scheme_counts[scheme_key] = scheme_counts.get(scheme_key, 0) + 1

        if row.get("transition") == "model_observation":
            payload = row.get("payload")
            status = payload.get("status") if isinstance(payload, dict) else None
            status_key = status if isinstance(status, str) and status else "unknown"
            model_observation_status_counts[status_key] = (
                model_observation_status_counts.get(status_key, 0) + 1
            )

    return ProjectInvariantMeasurements(
        project=project,
        event_count=event_count,
        declared_lineage_event_count=declared_lineage_event_count,
        distinct_lineage_tokens=tuple(sorted(distinct_tokens)),
        unresolvable_lineage_tokens=tuple(sorted(unresolvable_tokens)),
        unresolvable_lineage_value_count=unresolvable_value_count,
        ambiguous_lineage_event_count=ambiguous_lineage_event_count,
        scheme_counts=scheme_counts,
        undeclared_agent_author_event_count=undeclared_agent_author_event_count,
        model_observation_status_counts=model_observation_status_counts,
        snapshot_id=snapshot_id,
    )


_CONNINFO_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _parse_conninfo_keywords(dsn: str) -> dict[str, str] | None:
    """Parse the supported libpq keyword/value grammar without guessing."""
    result: dict[str, str] = {}
    i, n = 0, len(dsn)
    while i < n:
        while i < n and dsn[i].isspace():
            i += 1
        if i >= n:
            break
        matched = _CONNINFO_KEY_RE.match(dsn, i)
        if matched is None:
            return None
        key = matched.group(0).lower()
        i = matched.end()
        while i < n and dsn[i].isspace():
            i += 1
        if i >= n or dsn[i] != "=":
            return None
        i += 1
        while i < n and dsn[i].isspace():
            i += 1
        if i < n and dsn[i] == "'":
            i += 1
            chars: list[str] = []
            closed = False
            while i < n:
                ch = dsn[i]
                if ch == "\\" and i + 1 < n:
                    chars.append(dsn[i + 1])
                    i += 2
                    continue
                if ch == "'":
                    closed = True
                    i += 1
                    break
                chars.append(ch)
                i += 1
            if not closed:
                return None
            value = "".join(chars)
        else:
            start = i
            while i < n and not dsn[i].isspace():
                i += 1
            value = dsn[start:i]
        result[key] = value
    return result or None


def _keyword_value_identity(dsn: str) -> tuple[str, str, int, str] | None:
    keywords = _parse_conninfo_keywords(dsn)
    if keywords is None:
        return None
    database = keywords.get("dbname", "")
    if not database or "=" in database:
        return None
    host = keywords.get("host") or keywords.get("hostaddr") or ""
    if "," in host:
        return None
    host = host.strip().lower().rstrip(".")
    raw_port = keywords.get("port", "5432")
    if "," in raw_port:
        return None
    try:
        port = int(raw_port)
    except ValueError:
        return None
    return ("postgresql", host, port, database)


def _postgres_database_identity(dsn: str) -> tuple[str, str, int, str] | None:
    try:
        parsed = urlsplit(dsn)
        if parsed.scheme.lower() not in {"postgres", "postgresql"}:
            return _keyword_value_identity(dsn)
        options = parse_qs(parsed.query, keep_blank_values=True)
        host = parsed.hostname
        if host is None:
            host = options.get("host", [""])[0]
        host = unquote(host).strip().lower().rstrip(".")

        port = parsed.port
        if port is None:
            raw_port = options.get("port", ["5432"])[0]
            port = int(raw_port)

        database = unquote(parsed.path.lstrip("/").rstrip("/"))
        if not database:
            database = unquote(options.get("dbname", [""])[0])
        if not database:
            return None
        return ("postgresql", host, port, database)
    except (ValueError, UnicodeError):
        return None


def postgres_database_fingerprint(dsn: str) -> str | None:
    """Return the credential-free identity used by the suite gate.

    This mirrors Agent Suite's supported URI and libpq keyword/value parser.
    The normalization is part of the cross-component probe contract.
    """
    try:
        identity = _postgres_database_identity(dsn)
    except (ValueError, TypeError):
        return None
    if identity is None:
        return None
    material = "\0".join((identity[0], identity[1], str(identity[2]), identity[3]))
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def _probe_snapshot_id(conn: psycopg.Connection[dict[str, Any]]) -> str:
    row = conn.execute("SELECT txid_current_snapshot() AS snapshot").fetchone()
    if row is None or not isinstance(row["snapshot"], str) or not row["snapshot"]:
        raise psycopg.OperationalError("read-only probe returned no transaction snapshot")
    return "pg:" + row["snapshot"]


def _probe_load_bearing_fields() -> tuple[bool, str]:
    envelope: dict[str, Any] = {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": "project",
        "trust_domain_id": "trust",
        "event_id": "event",
        "entity": {"kind": "project", "id": "project"},
        "entity_seq": 1,
        "actor": {"principal_id": "agent:probe", "kind": "agent", "metadata": None},
        "signing": {
            "scheme_id": "ed25519",
            "key_id": "probe-key",
            "key_binding_event_hash": None,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None,
        "occurred_at": "2026-08-08T12:34:56.123456Z",
        "transition": "project_initialized",
        "payload": None,
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": None,
            "previous_project_event_hash": None,
        },
        "producer": {
            "harness": "probe",
            "harness_version": "1",
            "model": None,
            "model_lineage": None,
        },
    }
    try:
        validate_load_bearing_fields(envelope)
    except RegistaError as exc:
        return False, f"complete load-bearing fixture was refused: {exc.code}"

    del envelope["producer"]["harness"]
    try:
        validate_load_bearing_fields(envelope)
    except RegistaError as exc:
        if exc.code is ErrorCode.LOAD_BEARING_FIELD_MISSING:
            pass
        else:
            return False, f"missing load-bearing field used {exc.code}, not the named error"
    else:
        return False, "missing producer.harness was accepted"

    envelope["producer"]["harness"] = "   "
    try:
        validate_load_bearing_fields(envelope)
    except RegistaError as exc:
        if exc.code is ErrorCode.LOAD_BEARING_FIELD_MISSING:
            return True, (
                "complete fixture accepted; missing and whitespace-only "
                "producer.harness were refused"
            )
        return False, f"whitespace load-bearing field used {exc.code}, not the named error"
    return False, "whitespace-only producer.harness was accepted"


def _probe_first_write_admission() -> tuple[bool, str]:
    try:
        first_write_admission(
            gate_passed=True,
            event_count=0,
            head_hash=None,
            transition="project_initialized",
        )
    except RegistaError as exc:
        return False, f"empty gated first write was refused: {exc.code}"

    denials = (
        (False, 0, None, 0, False, "project_initialized", ErrorCode.GENESIS_GATE_NOT_PASSED),
        (True, 1, None, 0, False, "project_initialized", ErrorCode.GENESIS_ALREADY_WRITTEN),
        (True, 0, b"head", 0, False, "project_initialized", ErrorCode.GENESIS_ALREADY_WRITTEN),
        (True, 0, None, 1, False, "project_initialized", ErrorCode.GENESIS_ALREADY_WRITTEN),
        (True, 0, None, 0, True, "project_initialized", ErrorCode.GENESIS_ALREADY_WRITTEN),
        (True, 0, None, 0, False, "not_project_initialized", ErrorCode.GENESIS_INVALID),
    )
    for (
        gate_passed,
        event_count,
        head_hash,
        archived_count,
        identity_present,
        transition,
        expected,
    ) in denials:
        try:
            first_write_admission(
                gate_passed=gate_passed,
                event_count=event_count,
                head_hash=head_hash,
                archived_event_count=archived_count,
                identity_present=identity_present,
                transition=transition,
            )
        except RegistaError as exc:
            if exc.code is not expected:
                return False, f"denial used {exc.code}, expected {expected}"
        else:
            return False, f"denial with expected code {expected} was accepted"
    return True, (
        "empty gated first write accepted; gate, existing data, head, and "
        "transition denials refused"
    )


def discover_projects(dsn: str) -> list[str]:
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        rows = conn.execute(
            "SELECT schema_name FROM public.projects ORDER BY schema_name"
        ).fetchall()
    return [str(row[0]) for row in rows]


#: Rows are streamed in batches of this size rather than materialised at once,
#: so a probe's resident memory is bounded by the batch and not by the table.
PROBE_FETCH_BATCH = 2000

#: The measurement needs five scalars and two narrow objects per event, not the
#: whole row. ``canonical_envelope`` (a bytea holding the signed envelope) and
#: ``payload`` together dominate the table — on the estate's largest schema they
#: are 330 MB and 135 MB against 14 MB of ``actor_metadata`` — so both are
#: reduced server-side to just the fields the measurement reads. ``->`` is used
#: throughout rather than ``->>`` to preserve JSON types: a non-string lineage
#: must keep reading as an unresolvable *value*, not as the token ``"42"``.
#:
#: A ``canonical_envelope`` that is not decodable UTF-8, or not parseable as
#: JSON, raises here rather than reading as "no declared lineage". That is
#: deliberate and is a change from the row-parsing path, which was lenient: a
#: measurement whose job is to surface undeclared lineage must not answer "none
#: declared" when what it actually found was corruption.
#: ``invariant_probe_report`` catches it and names the project in ``errors``,
#: which fails that project's check rather than the whole process.
_PROBE_QUERY = """
SELECT
  e.actor_kind,
  jsonb_build_object('model_lineage', e.actor_metadata -> 'model_lineage')
    AS actor_metadata,
  e.on_behalf_of,
  e.scheme_id,
  e.transition,
  CASE WHEN e.transition = 'model_observation' THEN jsonb_build_object(
         'status', e.payload -> 'status',
         'observed_model_lineage', e.payload -> 'observed_model_lineage')
  END AS payload,
  (env.doc -> 'version' = '6'::jsonb
   AND jsonb_typeof(env.doc -> 'producer') = 'object') AS envelope_producer_present,
  env.doc -> 'producer' -> 'model_lineage' AS envelope_model_lineage
FROM events e
LEFT JOIN LATERAL (
  SELECT CASE
    WHEN e.canonical_envelope IS NOT NULL
    THEN convert_from(e.canonical_envelope, 'UTF8')::jsonb
  END AS doc
) env ON true
"""


#: Spelling variants that must be refused. Every one of these was observed in,
#: or is the obvious near-miss of, a token the estate actually wrote: versioned
#: family names, bare vendor and bare size names, provider-qualified ids,
#: prefixed forks, harness names mistaken for models, and whitespace or case
#: variants. WI-285 exists because free text compared by exact string let these
#: read as distinct lineages and so manufacture false review independence, and a
#: check that refuses only one hardcoded variant would not have caught it.
_REJECTED_LINEAGE_VARIANTS: tuple[object, ...] = (
    "claude-opus-5",
    "claude-opus-4-8",
    "glm-5.2",
    "GLM-5.2",
    "gpt-5.6-sol",
    "openai/gpt-5.6-sol",
    "nemotron-3-ultra",
    "claude",
    "opus",
    "gpt",
    "umans-glm-5.2",
    "opencode",
    "codex",
    "gpt-codex",
    "kimi-k3",
    " claude-opus ",
    "CLAUDE-OPUS",
    "claude-opus\n",
    "",
    "   ",
    42,
    None,
    ["claude-opus"],
)


def _measure_closed_registry() -> tuple[bool, str]:
    """Exercise the write-path validator, not the registry's own membership.

    The naive form of this check — asserting every registered family validates —
    is a tautology: ``validate_model_lineage`` accepts exactly the registry, so
    it cannot fail however broken the ingress is. What is worth measuring is the
    surface a caller actually reaches: ``validate_actor_metadata`` and
    ``validate_delegation_chain``, the two functions every append path routes
    through. Both must accept each canonical family and refuse each variant with
    ``INVALID_MODEL_LINEAGE``.
    """
    accepted: list[str] = []
    for family in sorted(MODEL_LINEAGE_FAMILIES):
        try:
            validate_actor_metadata({"model_lineage": family})
            validate_delegation_chain(
                {"principal_id": "probe:agent", "principal_kind": "agent",
                 "principal_lineage": family}
            )
        except RegistaError:
            accepted.append(family)
    admitted: list[str] = []
    for variant in _REJECTED_LINEAGE_VARIANTS:
        if variant is None:
            # An explicit null is "undeclared", which is a legitimate state that
            # reads as UNKNOWN downstream; it must not be refused at ingress.
            continue
        for surface in ("actor_metadata", "on_behalf_of"):
            try:
                if surface == "actor_metadata":
                    validate_actor_metadata({"model_lineage": variant})
                else:
                    validate_delegation_chain(
                        {"principal_id": "probe:agent", "principal_kind": "agent",
                         "principal_lineage": variant}
                    )
            except RegistaError as exc:
                if exc.code is not ErrorCode.INVALID_MODEL_LINEAGE:
                    admitted.append(f"{surface}:{variant!r}")
            else:
                admitted.append(f"{surface}:{variant!r}")
    if accepted or admitted:
        return False, (
            f"canonical families refused: {accepted or 'none'}; "
            f"variants admitted: {admitted or 'none'}"
        )
    return True, (
        f"{len(MODEL_LINEAGE_FAMILIES)} canonical families accepted and "
        f"{len(_REJECTED_LINEAGE_VARIANTS) - 1} spelling variants refused at "
        "both write-path surfaces"
    )


def probe_project(dsn: str, project: str) -> ProjectInvariantMeasurements:
    validate_project_name(project)
    with psycopg.connect(dsn, connect_timeout=5, row_factory=dict_row) as conn:
        with conn.transaction():
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            conn.execute(SQL("SET LOCAL search_path TO {}").format(Identifier(project)))
            snapshot_id = _probe_snapshot_id(conn)
            # A server-side cursor: the measurement is scheduled every five
            # minutes and the event table only grows, so it must never depend on
            # the whole population fitting in the prober's memory.
            with conn.cursor(name="regista_invariant_probe", row_factory=dict_row) as cur:
                cur.itersize = PROBE_FETCH_BATCH
                cur.execute(_PROBE_QUERY)
                return measure_event_rows(project, cur, snapshot_id=snapshot_id)


def invariant_probe_report(dsn: str, projects: Iterable[str]) -> dict[str, Any]:
    measurements: list[ProjectInvariantMeasurements] = []
    errors: list[dict[str, str]] = []
    for project in projects:
        try:
            measurements.append(probe_project(dsn, project))
        except (ValueError, psycopg.Error) as exc:
            errors.append({"project": project, "error_type": type(exc).__name__})
    closed_registry, registry_detail = _measure_closed_registry()
    load_bearing_ok, load_bearing_detail = _probe_load_bearing_fields()
    first_write_ok, first_write_detail = _probe_first_write_admission()
    store_fingerprint = postgres_database_fingerprint(dsn)
    return {
        "component": "regista",
        "probe_version": 1,
        "ok": closed_registry and load_bearing_ok and first_write_ok and not errors,
        "checks": [
            {
                "id": "regista.store_invariant_measurements",
                "status": "measured" if not errors else "fail",
                "store_fingerprint": store_fingerprint,
                "projects": [measurement.to_dict() for measurement in measurements],
                "errors": errors,
            },
            {
                "id": "regista.closed_lineage_registry",
                "status": "pass" if closed_registry else "fail",
                "detail": registry_detail,
            },
            {
                "id": "regista.load_bearing_fields_refused",
                "status": "pass" if load_bearing_ok else "fail",
                "detail": load_bearing_detail,
            },
            {
                "id": "regista.first_write_admission",
                "status": "pass" if first_write_ok else "fail",
                "detail": first_write_detail,
            },
        ],
    }
