from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

from ._connection import validate_project_name
from ._errors import ErrorCode, RegistaError
from ._lineage import MODEL_LINEAGE_FAMILIES, validate_model_lineage


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


def _event_lineages(row: dict[str, Any]) -> list[tuple[object, bool]]:
    result: list[tuple[object, bool]] = []
    actor_kind = row.get("actor_kind")
    actor_is_agent = isinstance(actor_kind, str) and actor_kind.strip().lower() == "agent"
    envelope = row.get("canonical_envelope")
    if envelope is not None:
        try:
            parsed = json.loads(bytes(envelope))
        except (TypeError, ValueError, UnicodeDecodeError):
            parsed = None
        if isinstance(parsed, dict) and parsed.get("version") == 6:
            producer = parsed.get("producer")
            if isinstance(producer, dict):
                result.append((producer.get("model_lineage"), actor_is_agent))
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
    )


def discover_projects(dsn: str) -> list[str]:
    with psycopg.connect(dsn, connect_timeout=5) as conn:
        rows = conn.execute(
            "SELECT schema_name FROM public.projects ORDER BY schema_name"
        ).fetchall()
    return [str(row[0]) for row in rows]


def probe_project(dsn: str, project: str) -> ProjectInvariantMeasurements:
    validate_project_name(project)
    with psycopg.connect(dsn, connect_timeout=5, row_factory=dict_row) as conn:
        with conn.transaction():
            conn.execute("SET TRANSACTION READ ONLY")
            conn.execute(SQL("SET LOCAL search_path TO {}").format(Identifier(project)))
            rows = conn.execute(
                "SELECT actor_kind, actor_metadata, on_behalf_of, canonical_envelope, "
                "scheme_id, transition, payload FROM events"
            ).fetchall()
    return measure_event_rows(project, rows)


def invariant_probe_report(dsn: str, projects: Iterable[str]) -> dict[str, Any]:
    measurements: list[ProjectInvariantMeasurements] = []
    errors: list[dict[str, str]] = []
    for project in projects:
        try:
            measurements.append(probe_project(dsn, project))
        except (ValueError, psycopg.Error) as exc:
            errors.append({"project": project, "error_type": type(exc).__name__})
    closed_registry = all(
        validate_model_lineage(family, field="probe") == family
        for family in MODEL_LINEAGE_FAMILIES
    )
    try:
        validate_model_lineage("GLM-5.2", field="probe")
    except RegistaError as exc:
        closed_registry = closed_registry and exc.code is ErrorCode.INVALID_MODEL_LINEAGE
    else:
        closed_registry = False
    return {
        "component": "regista",
        "probe_version": 1,
        "ok": closed_registry and not errors,
        "checks": [
            {
                "id": "regista.store_invariant_measurements",
                "status": "measured" if not errors else "fail",
                "projects": [measurement.to_dict() for measurement in measurements],
                "errors": errors,
            },
            {
                "id": "regista.closed_lineage_registry",
                "status": "pass" if closed_registry else "fail",
                "detail": "canonical families are accepted and spelling variants are refused",
            },
        ],
    }
