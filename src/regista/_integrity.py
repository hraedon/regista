from __future__ import annotations

import importlib.metadata

from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError
from ._migrations import check_migrations_current


def _installed_version() -> str:
    # The distribution renamed to regista-hraedon for PyPI (the import name
    # stays regista); pre-rename installs still carry the old name. A miss on
    # both names means broken packaging metadata — 0.0.0 then fails workflow
    # compatibility loudly rather than masquerading as a real version.
    for dist in ("regista-hraedon", "regista"):
        try:
            return importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            continue
    return "0.0.0"


REGISTA_VERSION = _installed_version()


def _parse_semver(s: str) -> tuple[int, int, int]:
    try:
        core = s.split("-", 1)[0].split("+", 1)[0]
        parts = core.split(".")
        if len(parts) != 3:
            raise ValueError(f"Expected 3 version components, got {len(parts)}")
        return (int(parts[0]), int(parts[1]), int(parts[2]))
    except (ValueError, IndexError) as e:
        raise RegistaError(
            ErrorCode.WORKFLOW_VERSION_INCOMPATIBLE,
            f"Invalid semantic version {s!r}: {e}",
        ) from e


def check_integrity(mgr: ConnectionManager, *, read_only: bool = False) -> list[str]:
    issues: list[str] = []

    check_migrations_current(mgr, read_only=read_only)

    with mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT workflow_name, version, regista_version FROM workflow_registry"
        ).fetchall()

    lib_ver = _parse_semver(REGISTA_VERSION)

    for row in rows:
        wf_name = row["workflow_name"]
        wf_ver = row["version"]
        wf_sub_str = row["regista_version"]

        wf_sub = _parse_semver(wf_sub_str)

        if lib_ver[0] != wf_sub[0]:
            issues.append(
                f"Workflow {wf_name!r} v{wf_ver}: regista_version major mismatch "
                f"(workflow={wf_sub[0]}, library={lib_ver[0]})"
            )
        elif lib_ver < wf_sub:
            issues.append(
                f"Workflow {wf_name!r} v{wf_ver}: requires regista "
                f"{wf_sub_str}, library is {REGISTA_VERSION}"
            )

    if issues:
        raise RegistaError(
            ErrorCode.WORKFLOW_VERSION_INCOMPATIBLE,
            "Workflow version incompatibilities: " + "; ".join(issues),
            detail={"issues": issues},
        )

    return issues
