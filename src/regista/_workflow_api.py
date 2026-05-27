from __future__ import annotations

from pathlib import Path

import psycopg.types.json
from psycopg.sql import SQL

from ._errors import ErrorCode, RegistaError
from ._observability import Metrics, OpTimer
from ._types import WorkflowVersion
from ._workflow import parse_and_validate


def register_workflow(
    mgr,
    metrics: Metrics,
    project: str,
    yaml_content: str,
) -> WorkflowVersion:
    from ._workflow import compute_content_hash, compute_content_hash_from_dict

    timer = OpTimer(project, "register_workflow")
    try:
        wf = parse_and_validate(yaml_content)
        content_hash = compute_content_hash(wf)
        with mgr.transaction() as conn:
            existing = conn.execute(
                SQL(
                    "SELECT workflow_name, version, regista_version, registered_at, "
                    "content_hash, definition "
                    "FROM workflow_registry WHERE workflow_name = %s AND version = %s"
                ),
                [wf.name, wf.version],
            ).fetchone()
            if existing is not None:
                existing_hash = existing["content_hash"]
                if existing_hash is None:
                    existing_hash = compute_content_hash_from_dict(existing["definition"])
                    conn.execute(
                        SQL(
                            "UPDATE workflow_registry SET content_hash = %s "
                            "WHERE workflow_name = %s AND version = %s"
                        ),
                        [existing_hash, wf.name, wf.version],
                    )
                if existing_hash != content_hash:
                    raise RegistaError(
                        ErrorCode.WORKFLOW_VERSION_CONFLICT,
                        f"Workflow {wf.name!r} v{wf.version} already registered "
                        f"with different content",
                        detail={"workflow_name": wf.name, "version": wf.version},
                    )
                timer.log("ok", detail=f"idempotent:{wf.name} v{wf.version}")
                return WorkflowVersion(
                    name=existing["workflow_name"],
                    version=existing["version"],
                    regista_version=existing["regista_version"],
                    registered_at=existing["registered_at"],
                )

            row = conn.execute(
                SQL(
                    "INSERT INTO workflow_registry "
                    "(workflow_name, version, regista_version, definition, content_hash) "
                    "VALUES (%s, %s, %s, %s, %s) "
                    "RETURNING registered_at"
                ),
                [
                    wf.name, wf.version, wf.regista_version,
                    psycopg.types.json.Jsonb(wf.to_dict()),
                    content_hash,
                ],
            ).fetchone()

        metrics.inc("workflows_registered", project)
        timer.log("ok", detail=wf.name)
        return WorkflowVersion(
            name=wf.name,
            version=wf.version,
            regista_version=wf.regista_version,
            registered_at=row["registered_at"],
        )
    except RegistaError:
        timer.log("error")
        raise


def register_workflow_file(
    mgr,
    metrics: Metrics,
    project: str,
    parse_workflow_yaml,
    yaml_dump,
    path: str | Path,
) -> WorkflowVersion:
    from ._workflow_compose import resolve_includes

    p = Path(path)
    raw_text = p.read_text()
    raw_dict = parse_workflow_yaml(raw_text)
    if "extends" in raw_dict:
        composed, _ = resolve_includes(p, compose_root=p.parent)
        composed_yaml = yaml_dump(composed, default_flow_style=False, sort_keys=False)
    else:
        composed_yaml = raw_text
    return register_workflow(mgr, metrics, project, composed_yaml)


def get_workflow(
    mgr,
    project: str,
    workflow_name: str,
    version: int,
):
    from ._types import WorkflowDefinition

    timer = OpTimer(project, "get_workflow")
    with mgr.transaction() as conn:
        row = conn.execute(
            "SELECT definition FROM workflow_registry "
            "WHERE workflow_name = %s AND version = %s",
            [workflow_name, version],
        ).fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.WORKFLOW_NOT_REGISTERED,
            f"Workflow {workflow_name!r} v{version} not found",
        )
    timer.log("ok", detail=f"{workflow_name} v{version}")
    return WorkflowDefinition.from_dict(row["definition"])
