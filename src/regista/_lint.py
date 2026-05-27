from __future__ import annotations

import jsonschema

from ._types import Event

_RECOMMENDED_FIELDS = ("model", "provider", "role_source")
_VALID_ROLE_SOURCES = ("config", "env", "prompt")


def validate_actor_metadata(
    event: Event,
    expected_schema: dict | None = None,
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
