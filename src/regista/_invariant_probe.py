from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import uuid
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

import psycopg
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

from ._connection import validate_project_name
from ._contract import validate_actor_metadata, validate_delegation_chain
from ._errors import ErrorCode, RegistaError
from ._genesis import first_write_admission, validate_load_bearing_fields
from ._keys import KeySet
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


# ---------------------------------------------------------------------------
# regista.actor_boundary_signing (WI-326)
#
# The genesis gate requires a *behavioral* proof that signing happens at the
# actor boundary, and states the property it wants observed: that no
# service-held keyset can sign as arbitrary principals.
#
# SCOPE LIMIT, SO THIS IS NOT READ AS MORE THAN IT IS. Plan 023 R-10 has two
# sentences. This check proves the second — that a keyset cannot sign as a
# principal it is not bound to — which is the one the gate's own wording asks a
# probe to observe. It does NOT prove the first in its strongest form, that
# private key material never leaves the actor: a process holding principal P's
# key can still sign as P, and that is by construction of the current writers.
# Moving custody out of process is `regista.client_signer` and the lifecycle
# possession ceremony, not something a probe can assert. Anyone reading a green
# check here should read it as "no arbitrary-principal signing", not "no
# service-held keys".
#
# agent-suite's operator contract (Plan 023 R-10) is explicit that
# "key-file or configuration inspection is not evidence" — so nothing below
# reads a key file's ``principal_id`` and reports it. Instead the probe builds a
# synthetic keyset that deliberately holds exactly one usable actor key, bound to
# ONE principal, and then attempts real signing writes as a DIFFERENT principal
# through the unmodified production paths, observing the named refusal.
#
# The two attempted paths are the two that sign an event onto a project chain:
#   * ``_genesis.append_v6_genesis``  — opens the epoch
#   * ``_v6_writer.append_v6_event``  — every ordinary event thereafter
# Between them they cover the actor-boundary comparison in ``_genesis_key`` and
# the one in ``_v6_writer._writer_key`` — and the latter is the *same function*
# ``_trust_log_writer`` imports and calls for trust-log genesis and trust-log
# appends (``_trust_log_writer.py`` line 69's import), so proving it here proves
# it for that writer too. Not covered: the verification-side
# ``_principal_keys.verify_principal_binding``, which is a read path and refuses
# under the same code but is not a signing attempt.
# Both are driven here over ``_in_memory_v6.InMemoryV6Connection``, the WI-287
# D2 parity backend, whose whole design point is that those two functions run
# **unmodified** against it (see that module's docstring: "byte-for-byte the
# Postgres implementation, executing over a different row store"). So the code
# refusing the unbound principal here is the code production writes with.
#
# WHY A SYNTHETIC STORE, STATED PLAINLY. The invariant proven is a LIBRARY
# property — where the signing boundary is enforced — not a property of any
# particular store's contents. The probe also runs against ``REGISTA_DSN`` in
# gate context and must not write a durable row anywhere, and a signing proof
# necessarily *writes* (the positive control has to produce a real signature and
# a real event, or the refusals prove nothing about a path that can sign at all).
# Those two facts point the same way: the behavioral attempt runs against an
# ephemeral in-memory epoch. The check reports this in its ``basis`` field
# rather than letting a reader assume the live store was exercised.
#
# WHAT WOULD MAKE THIS VACUOUS, AND WHY IT ISN'T. A check that only observed
# "the unbound principal was refused" could be satisfied by a keyset that simply
# had no key to offer. So the probe first asserts the opposite: that
# ``KeySet.resolve_signing_key`` *does* hand the service's own key to an
# arbitrary principal (it falls through to ``active_key()`` when the principal
# has no key of its own). The service-held keyset is therefore willing; the
# actor-boundary comparison in ``_writer_key`` / ``_genesis_key`` is the only
# thing that refuses. That is the invariant, and it is why the positive control
# and the willingness assertion are part of the proof rather than decoration.
# ---------------------------------------------------------------------------

#: The single principal the probe's synthetic keyset binds a usable actor key to.
#: A ``service:`` id on purpose — this stands in for exactly the thing the
#: invariant forbids, a service holding signing material.
_BOUNDARY_KEY_HOLDER = "service:regista-invariant-probe"

#: The principals the probe attempts to sign AS. Nothing in the keyset is bound to
#: either, so every attempt below is an unbound-principal signing attempt. Two of
#: them, of two different §2.1 principal kinds, because the claim under test is
#: "cannot sign as *arbitrary* principals" — one id would leave open the reading
#: that only same-kind impersonation is refused.
_BOUNDARY_UNBOUND_SERVICE = "service:regista-invariant-probe-unbound"
_BOUNDARY_UNBOUND_AGENT = "agent:regista-invariant-probe-unbound"

#: A principal whose key IS bound to it but carries role ``auditor``. Covers the
#: role-mismatch half of the requirement ("the key is absent/role-mismatched").
_BOUNDARY_AUDITOR = "agent:regista-invariant-probe-auditor"

#: ``occurred_at`` for the synthetic envelopes. A fixed literal, matching
#: ``_probe_load_bearing_fields``: genesis validation does not check freshness, so
#: a clock read would add a dependency that can only fail, never inform.
_BOUNDARY_OCCURRED_AT = "2026-08-08T12:34:56.123456Z"


def _boundary_digest(tag: str) -> str:
    """A well-formed ``sha256:<64 hex>`` fixture digest for a synthetic envelope."""
    return "sha256:" + hashlib.sha256(("regista.actor_boundary/" + tag).encode()).hexdigest()


@dataclass(frozen=True)
class _BoundaryKey:
    principal_id: str
    key_id: str
    role: str
    seed: bytes
    public_key: bytes

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(self.public_key).decode("ascii")

    @property
    def fingerprint(self) -> str:
        return "ed25519:sha256:" + hashlib.sha256(self.public_key).hexdigest()


def _generate_boundary_key(principal_id: str, role: str) -> _BoundaryKey:
    from nacl.signing import SigningKey

    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key)
    return _BoundaryKey(
        principal_id=principal_id,
        key_id="pk_probe_" + hashlib.sha256(public_key).hexdigest()[:16],
        role=role,
        seed=bytes(signing_key),
        public_key=public_key,
    )


def _write_boundary_keyset(
    directory: Path,
    keys: Iterable[_BoundaryKey],
    env_vars: dict[str, str],
) -> Path:
    """Write a real ``KeySet`` key file whose secrets live only in process env.

    Two reasons the seeds go through ``secret_ref: env:...`` rather than inline.
    First, a freshly generated Ed25519 private seed should not touch the
    filesystem at all when it does not have to — the file this writes carries
    public material and a reference, nothing more. Second, an inline secret makes
    ``KeySet._load`` log ``keys.plaintext_at_rest`` at WARNING, and this probe is
    on a five-minute schedule: 288 warnings a day naming a throwaway key would be
    pure noise in front of the one that would matter.

    ``env_vars`` is filled in for the caller to unset — see
    :func:`_probe_actor_boundary_signing`'s ``finally``.
    """
    entries: list[dict[str, Any]] = []
    for key in keys:
        # Randomized per call: no ambient variable can collide with it, so the
        # probe cannot be perturbed by the environment it happens to run in.
        var = "REGISTA_INVARIANT_PROBE_SEED_" + uuid.uuid4().hex
        env_vars[var] = base64.b64encode(key.seed).decode("ascii")
        entries.append(
            {
                "key_id": key.key_id,
                "scheme": "ed25519",
                "alg": "Ed25519",
                "secret_ref": f"env:{var}",
                "encoding": "base64",
                "public_key": key.public_key_b64,
                "principal_id": key.principal_id,
                "role": key.role,
                "status": "active",
            }
        )
    target = directory / "actor_boundary_probe_keys.json"
    target.write_text(json.dumps({"keys": entries}), encoding="utf-8")
    return target


def _boundary_genesis_envelope(
    *,
    actor_id: str,
    actor_kind: str,
    signing_key: _BoundaryKey,
) -> dict[str, Any]:
    """A complete ``project_initialized`` envelope for the synthetic epoch.

    ``actor_id`` and ``signing_key`` are independent parameters *on purpose*: the
    whole point is to be able to declare an actor the signing key is not bound to
    and watch the writer refuse it.
    """
    project = str(uuid.uuid4())
    checkpoint = {
        "checkpoint_seq": 1,
        "head_event_hash": _boundary_digest("checkpoint-head"),
        "document_digest": _boundary_digest("checkpoint-doc"),
    }
    return {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": project,
        "trust_domain_id": str(uuid.uuid4()),
        "event_id": str(uuid.uuid4()),
        "entity": {"kind": "project", "id": project},
        "entity_seq": 1,
        "actor": {"principal_id": actor_id, "kind": actor_kind, "metadata": None},
        "signing": {
            "scheme_id": "ed25519",
            "key_id": signing_key.key_id,
            "key_binding_event_hash": None,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None,
        "occurred_at": _BOUNDARY_OCCURRED_AT,
        "transition": "project_initialized",
        "payload": {
            "trust_domain_core_digest": _boundary_digest("trust-domain-core"),
            "genesis_document_digest": _boundary_digest("genesis-document"),
            "trust_log_checkpoint": dict(checkpoint),
            "previous_epoch": {
                "event_count": 0,
                "genesis_event_hash": None,
                "head_event_hash": None,
                "head_hash_construction": "sha256(canonical_envelope||signature)",
                "max_global_seq": None,
                "scheme_counts": {},
            },
            "bootstrap_key_acceptance": {
                "principal_id": actor_id,
                "key_id": signing_key.key_id,
                "scheme_id": "ed25519",
                "public_key": signing_key.public_key_b64,
                "fingerprint": signing_key.fingerprint,
                "trust_event_hash": _boundary_digest("trust-event"),
                "trust_log_checkpoint": dict(checkpoint),
                "scopes": {
                    "entity_kinds": ["project", "principal", "workflow", "work_item"],
                    "transitions": None,
                    "may_accept_keys": True,
                    "may_sign_checkpoints": True,
                    "may_sign_bundles": False,
                },
            },
        },
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": None,
            "previous_project_event_hash": None,
        },
        "producer": {
            "harness": "regista-invariant-probe",
            "harness_version": "1",
            "model": None,
            "model_lineage": None,
        },
    }


def _probe_actor_boundary_signing() -> tuple[bool, str]:
    """Attempt real signing writes as a principal no key is bound to.

    Returns ``(ok, detail)``. ``ok`` is true only when every attempt below
    behaved: the two positive controls signed, and every unbound / role-mismatched
    attempt was refused with its **named** error code. Any other outcome — a
    refusal under a different code, an acceptance, or an unexpected exception —
    returns false with a reason, because the only safe reading of "something
    happened here that this probe does not model" is that the invariant is
    unproven.
    """
    try:
        return _run_actor_boundary_attempts()
    except RegistaError as exc:
        return False, f"the boundary probe itself was refused with {exc.code}"
    except Exception as exc:
        # Deliberately bare: a probe that cannot complete has not proven the
        # invariant, and the only safe status for "unproven" is fail.
        return False, f"the boundary probe raised {type(exc).__name__} and proved nothing"


def _run_actor_boundary_attempts() -> tuple[bool, str]:
    holder = _generate_boundary_key(_BOUNDARY_KEY_HOLDER, "actor")
    auditor = _generate_boundary_key(_BOUNDARY_AUDITOR, "auditor")
    env_vars: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="regista-actor-boundary-") as directory:
        try:
            # Order matters: KeySet's ``active_key()`` fallback returns the FIRST
            # active entry, so the holder must be written first for the
            # service-held-keyset fallback the check relies on to be its key.
            key_file = _write_boundary_keyset(Path(directory), (holder, auditor), env_vars)
            os.environ.update(env_vars)
            return _attempt_boundary_writes(
                KeySet(str(key_file)), holder=holder, auditor=auditor
            )
        finally:
            for var in env_vars:
                os.environ.pop(var, None)


def _boundary_epoch(key_set: KeySet) -> Any:
    """An ephemeral in-memory v6 connection manager: no Postgres, no durable row."""
    from ._event_store import InMemoryEventStore
    from ._in_memory_v6 import InMemoryV6ConnectionManager

    store = InMemoryEventStore()
    store.bind_keys(key_set)
    return InMemoryV6ConnectionManager(store.v6_rows)


def _boundary_event_count(manager: Any) -> int:
    with manager.read_only_transaction() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
    return 0 if row is None else int(row["n"])


def _attempt_boundary_writes(
    key_set: KeySet,
    *,
    holder: _BoundaryKey,
    auditor: _BoundaryKey,
) -> tuple[bool, str]:
    from ._genesis import append_v6_genesis
    from ._v6_writer import Producer, append_v6_event

    # (0) The keyset is WILLING. Without this the refusals below could just mean
    # "there was no key to sign with", which proves nothing about the boundary.
    # ``resolve_signing_key`` finds no key bound to these principals and falls
    # through to ``active_key()`` — the holder's, since it is written first in the
    # key file — which is precisely the service-held-keyset shape under test.
    for unbound in (_BOUNDARY_UNBOUND_SERVICE, _BOUNDARY_UNBOUND_AGENT):
        offered = key_set.resolve_signing_key(unbound)
        if offered.key_id != holder.key_id:
            return False, (
                "the synthetic service keyset did not offer its own key to an "
                f"unbound principal (offered {offered.key_id!r} for {unbound!r}), so "
                "the attempts below could not distinguish an enforced boundary from "
                "an absent key"
            )

    # The two genesis envelopes are the SAME object with one field changed — the
    # actor's principal id (and its echo in the acceptance block, which §5.8
    # requires to equal it). Derived by copy rather than built twice so "the only
    # difference is who is claimed to be acting" is a fact about the code and not
    # a claim in a comment.
    bound_genesis = _boundary_genesis_envelope(
        actor_id=holder.principal_id, actor_kind="system", signing_key=holder
    )
    unbound_genesis = deepcopy(bound_genesis)
    unbound_genesis["actor"]["principal_id"] = _BOUNDARY_UNBOUND_SERVICE
    unbound_genesis["payload"]["bootstrap_key_acceptance"]["principal_id"] = (
        _BOUNDARY_UNBOUND_SERVICE
    )

    # (1) Unbound-principal GENESIS: append_v6_genesis must refuse before signing.
    refused = _boundary_epoch(key_set)
    with refused.transaction() as conn:
        outcome = _expect_refusal(
            lambda: append_v6_genesis(conn, key_set, unbound_genesis, gate_passed=True),
            ErrorCode.ACTOR_SIGNER_MISMATCH,
            "unbound-principal genesis",
        )
    if outcome is not None:
        return False, outcome
    if _boundary_event_count(refused) != 0:
        return False, "the refused unbound-principal genesis still wrote an event"

    # (2) Positive control: the SAME keyset, the same code path, the same envelope
    # bar the actor, signing as the principal the key IS bound to. Opens the epoch
    # attempt (3) needs, and shows the refusal above is the boundary rather than a
    # path that cannot sign at all.
    epoch = _boundary_epoch(key_set)
    with epoch.transaction() as conn:
        written = append_v6_genesis(conn, key_set, bound_genesis, gate_passed=True)
    if not getattr(written, "signature", b""):
        return False, "the bound-principal genesis produced no signature"

    producer = Producer(
        harness="regista-invariant-probe",
        harness_version="1",
        model=None,
        model_lineage=None,
    )

    def append(actor_id: str, actor_kind: str, key_id: str | None) -> Any:
        with epoch.transaction() as conn:
            return append_v6_event(
                conn,
                key_set,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="work_item_created",
                actor_id=actor_id,
                actor_kind=actor_kind,
                producer=producer,
                key_id=key_id,
            )

    # (3) Unbound-principal ORDINARY EVENT, twice: once letting the keyset choose
    # (it falls through to the service's own key — the exact "service-held keyset
    # signs as anyone" shape the gate is asking about), once naming that key
    # explicitly so no resolution rule can be credited with the refusal.
    before = _boundary_event_count(epoch)
    attempts: tuple[tuple[str, str, str, str | None, ErrorCode], ...] = (
        (
            "unbound-principal append (agent id, keyset chose the service key)",
            _BOUNDARY_UNBOUND_AGENT,
            "agent",
            None,
            ErrorCode.ACTOR_SIGNER_MISMATCH,
        ),
        (
            "unbound-principal append (service id, service key named explicitly)",
            _BOUNDARY_UNBOUND_SERVICE,
            "system",
            holder.key_id,
            ErrorCode.ACTOR_SIGNER_MISMATCH,
        ),
        (
            "role-mismatched append (auditor key, bound principal)",
            auditor.principal_id,
            "agent",
            auditor.key_id,
            ErrorCode.KEY_ROLE_NOT_PERMITTED,
        ),
    )
    for label, actor_id, actor_kind, key_id, expected in attempts:
        outcome = _expect_refusal(
            partial(append, actor_id, actor_kind, key_id), expected, label
        )
        if outcome is not None:
            return False, outcome
    if _boundary_event_count(epoch) != before:
        return False, "a refused unbound-principal append still wrote an event"

    # (4) Second positive control: the bound principal CAN append an ordinary
    # event. So attempt (3) failed on the actor boundary specifically, not on
    # something that would have refused any append at all.
    signed = append(holder.principal_id, "system", None)
    if not getattr(signed, "signature", b""):
        return False, "the bound-principal append produced no signature"

    return True, (
        f"{len(attempts) + 1} unbound/role-mismatched signing attempts were refused "
        f"with their named codes ({ErrorCode.ACTOR_SIGNER_MISMATCH.value}, "
        f"{ErrorCode.KEY_ROLE_NOT_PERMITTED.value}) by append_v6_genesis and "
        "append_v6_event, while the same keyset signed genesis and an ordinary "
        "event as the principal its key is bound to; the keyset had offered that "
        "same key to the unbound principal, so the boundary is what refused"
    )


def _expect_refusal(
    attempt: Callable[[], object], expected: ErrorCode, label: str
) -> str | None:
    """Run ``attempt``; return ``None`` if it raised ``expected``, else a reason.

    Deliberately narrow: a refusal under some *other* code is a failure, not a
    pass. Defence in depth means a weakened actor boundary would still be caught
    further down the writer (by key-binding anchor resolution, say) — under a
    different name. Accepting "refused somehow" would let the boundary rot while
    this check stayed green, which is the whole failure mode WI-326 exists to
    close.
    """
    try:
        attempt()
    except RegistaError as exc:
        if exc.code is expected:
            return None
        return (
            f"{label} was refused with {exc.code.value}, not the named "
            f"{expected.value}"
        )
    return f"{label} was ACCEPTED; the actor signing boundary is not enforced"


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
    boundary_ok, boundary_detail = _probe_actor_boundary_signing()
    store_fingerprint = postgres_database_fingerprint(dsn)
    return {
        "component": "regista",
        "probe_version": 1,
        "ok": (
            closed_registry
            and load_bearing_ok
            and first_write_ok
            and boundary_ok
            and not errors
        ),
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
            {
                "id": "regista.actor_boundary_signing",
                "status": "pass" if boundary_ok else "fail",
                "detail": boundary_detail,
                # Said out loud rather than left to be assumed: this one check
                # does NOT observe the store named by the DSN. It is a behavioral
                # attempt against an ephemeral in-memory v6 epoch, because what it
                # proves is a library property (where the signing boundary is
                # enforced) and because proving it requires *writing* — which the
                # probe may never do to a real store. The code exercised is the
                # unmodified production signing path; see the WI-326 block above.
                "basis": "behavioral_attempt_ephemeral_epoch",
                "paths_proven": [
                    "regista._genesis.append_v6_genesis",
                    "regista._v6_writer.append_v6_event",
                ],
            },
        ],
    }
