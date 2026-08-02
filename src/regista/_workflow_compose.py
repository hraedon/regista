from __future__ import annotations

from pathlib import Path
from typing import Any

from ._errors import ErrorCode, RegistaError
from ._workflow import parse_workflow_yaml, validate_and_build

MAX_INCLUDE_DEPTH = 8


def _deep_merge(
    parent: dict[str, Any], child: dict[str, Any], list_keys: dict[str, str],
) -> dict[str, Any]:
    result = dict(parent)
    for key, value in child.items():
        if key.endswith("__append"):
            base_key = key[:-8]
            if base_key in result:
                if isinstance(result[base_key], list) and isinstance(value, list):
                    result[base_key] = list(result[base_key]) + value
                else:
                    raise RegistaError(
                        ErrorCode.WORKFLOW_COMPOSE_ERROR,
                        f"__append target {base_key!r} is not a list",
                    )
            else:
                if isinstance(value, list):
                    result[base_key] = value
                else:
                    raise RegistaError(
                        ErrorCode.WORKFLOW_COMPOSE_ERROR,
                        f"__append target {base_key!r} is not a list",
                    )
        elif key == "__remove" and isinstance(value, bool) and value:
            continue
        elif isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result.get(key, {}), value, list_keys)
        elif isinstance(value, list) and isinstance(result.get(key), list):
            result[key] = _merge_lists(result.get(key, []), value, list_keys.get(key))
        else:
            result[key] = value
    return result


def _merge_lists(
    parent: list[dict[str, Any]], child: list[dict[str, Any]], key_by: str | None,
) -> list[dict[str, Any]]:
    if key_by is None:
        return child

    if key_by == "(name, from)":

        def _key(item: dict[str, Any]) -> Any:
            return (item.get("name"), item.get("from"))
    else:

        def _key(item: dict[str, Any]) -> Any:
            return item.get(key_by)

    merged = {}
    for p in parent:
        k = _key(p)
        if k is not None:
            merged[k] = p
    for c in child:
        k = _key(c)
        if k is None:
            continue
        if c == {"__remove": True} or c.get("__remove") is True:
            merged.pop(k, None)
            continue
        if k in merged:
            merged[k] = _deep_merge(merged[k], c, {})
        else:
            merged[k] = c

    kept = set(merged.keys())
    result = []
    for c in child:
        k = _key(c)
        if k is not None and k in kept:
            result.append(merged[k])
            kept.discard(k)
    for p in parent:
        k = _key(p)
        if k is not None and k in kept:
            result.append(merged[k])
            kept.discard(k)
    for k in list(kept):
        result.append(merged[k])
    return result


class SourceMap:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def record(self, path: str, source_file: str, source_line: int | None = None) -> None:
        self.entries.append({
            "json_pointer": path,
            "source_file": source_file,
            "source_line": source_line,
        })


def _resolve_file_path(base: Path, extends: str, compose_root: Path) -> Path:
    if not extends:
        raise RegistaError(
            ErrorCode.WORKFLOW_COMPOSE_ERROR,
            "extends value must be a non-empty string",
        )
    target = base.parent / extends
    try:
        resolved = target.resolve(strict=True)
    except FileNotFoundError as e:
        raise RegistaError(
            ErrorCode.WORKFLOW_COMPOSE_ERROR,
            f"extends file not found: {extends}",
        ) from e
    try:
        resolved.relative_to(compose_root.resolve())
    except ValueError as e:
        raise RegistaError(
            ErrorCode.WORKFLOW_COMPOSE_ERROR,
            f"extends path escapes compose_root: {extends}",
        ) from e
    return resolved


def resolve_includes(
    path: str | Path,
    *,
    compose_root: Path | None = None,
    _seen: frozenset[Path] | None = None,
    _memo: dict[Path, dict[str, Any]] | None = None,
    _depth: int = 0,
) -> tuple[dict[str, Any], SourceMap]:
    if _seen is None:
        _seen = frozenset()
    if _memo is None:
        _memo = {}

    target = Path(path) if isinstance(path, str) else path
    if compose_root is None:
        compose_root = target.parent
    canonical = target.resolve()

    if canonical in _seen:
        chain = " -> ".join(str(p.name) for p in (_seen | {canonical}))
        raise RegistaError(
            ErrorCode.WORKFLOW_COMPOSE_ERROR,
            f"Cycle detected in extends chain: {chain}",
        )

    if _depth > MAX_INCLUDE_DEPTH:
        raise RegistaError(
            ErrorCode.WORKFLOW_COMPOSE_ERROR,
            f"Maximum extends depth ({MAX_INCLUDE_DEPTH}) exceeded",
        )

    if canonical in _memo:
        return _memo[canonical], SourceMap()

    raw = target.read_text()
    data = parse_workflow_yaml(raw)

    source_map = SourceMap()
    for key in data:
        source_map.record(f"/{key}", target.name)

    if "extends" not in data or data["extends"] is None:
        _memo[canonical] = data
        return data, source_map

    parent_path = _resolve_file_path(target, data["extends"], compose_root)
    parent_data, parent_map = resolve_includes(
        parent_path,
        compose_root=compose_root,
        _seen=_seen | {canonical},
        _memo=_memo,
        _depth=_depth + 1,
    )

    merged = _deep_merge(parent_data, data, {
        "states": "(name, from)",
        "transitions": "(name, from)",
        "roles": "name",
        "work_item_types": "name",
        "link_types": "name",
    })

    if "extends" in merged:
        del merged["extends"]

    combined_map = SourceMap()
    combined_map.entries = parent_map.entries + source_map.entries
    _memo[canonical] = merged
    return merged, combined_map


def compose_workflow(path: str | Path) -> tuple[dict[str, Any], SourceMap]:
    """Resolve extends chain and merge into a single composed dict.

    Returns:
        Tuple of (composed_dict, SourceMap).
    """
    return resolve_includes(path)


def parse_file_with_composition(path: str | Path) -> Any:
    """Parse workflow file, resolving composition if extends: is present."""
    data, _ = compose_workflow(path)
    return validate_and_build(data, "")
