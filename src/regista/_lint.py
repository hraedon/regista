from __future__ import annotations

import os
from typing import Any

import jsonschema

from ._types import Event

_RECOMMENDED_FIELDS = ("model", "provider", "role_source")
_VALID_ROLE_SOURCES = ("config", "env", "prompt")

# WI-214: resolution hook for an authoring agent's model lineage. Faces map
# their harness/runtime identity into one of these (canonical first); the write
# path / callers can then stamp it onto actor_metadata so authoring ops always
# carry lineage and the cross-lineage gate stops tripping
# `agent_author_undeclared` for in-harness writes.
_MODEL_LINEAGE_ENV_VARS = (
    "REGISTA_MODEL_LINEAGE",
    "AGENT_MODEL_LINEAGE",
    "MODEL_LINEAGE",
)


def resolve_model_lineage(environ: dict[str, Any] | None = None) -> str | None:
    """Resolve the current agent's model lineage from the runtime environment.

    Probes ``REGISTA_MODEL_LINEAGE`` (canonical), then ``AGENT_MODEL_LINEAGE``,
    then ``MODEL_LINEAGE``; returns the first non-empty value (stripped), or
    ``None`` when no lineage is declared. ``environ`` overrides ``os.environ``
    for tests.
    """
    env = os.environ if environ is None else environ
    for var in _MODEL_LINEAGE_ENV_VARS:
        value = env.get(var)
        if value and value.strip():
            return value.strip()
    return None


def stamp_model_lineage(
    actor_metadata: dict[str, Any] | None,
    actor_kind: str,
    *,
    environ: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return *actor_metadata* with ``model_lineage`` stamped for agent actors.

    Pure (returns a new dict; never mutates the input). Non-agent actors are
    passed through unchanged. An already-declared ``model_lineage`` is never
    overwritten. When no lineage can be resolved the input is returned as-is, so
    a deployment without a configured lineage behaves exactly as before.
    """
    if actor_kind != "agent":
        return actor_metadata
    if isinstance(actor_metadata, dict) and actor_metadata.get("model_lineage"):
        return actor_metadata
    lineage = resolve_model_lineage(environ)
    if not lineage:
        return actor_metadata
    stamped = dict(actor_metadata) if isinstance(actor_metadata, dict) else {}
    stamped["model_lineage"] = lineage
    return stamped


def validate_actor_metadata(
    event: Event,
    expected_schema: dict[str, Any] | None = None,
) -> list[str]:
    issues: list[str] = []
    metadata = event.actor_metadata

    if metadata is None:
        issues.append("actor_metadata is null")
        return issues

    for field in _RECOMMENDED_FIELDS:
        if field not in metadata:
            issues.append(f"recommended field {field!r} missing")

    role_source = metadata.get("role_source")
    if role_source is not None and role_source not in _VALID_ROLE_SOURCES:
        issues.append(
            f"role_source should be one of {_VALID_ROLE_SOURCES}, "
            f"got {role_source!r}"
        )

    if expected_schema is not None:
        validator = jsonschema.Draft202012Validator(expected_schema)
        for error in validator.iter_errors(metadata):
            path = ".".join(str(p) for p in error.absolute_path) or "(root)"
            issues.append(f"schema violation at {path}: {error.message}")

    return issues


def actor_metadata_complete(
    events: list[Event],
    expected_keys: list[str],
) -> list[Event]:
    incomplete: list[Event] = []
    for evt in events:
        meta = evt.actor_metadata
        if meta is None:
            incomplete.append(evt)
            continue
        missing = any(k not in meta for k in expected_keys)
        if missing:
            incomplete.append(evt)
    return incomplete
