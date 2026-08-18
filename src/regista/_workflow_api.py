from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import psycopg.types.json
from psycopg.sql import SQL

from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError
from ._observability import Metrics, OpTimer
from ._types import WorkflowDefinition, WorkflowVersion
from ._workflow import parse_and_validate


def _append_workflow_registration_event(
    conn: Any,
    key_set: Any,
    wf: Any,
) -> None:
    """Append the signed ``workflow_registered`` event admission gate 1 resolves.

    No-op before genesis: the v6 writer refuses pre-epoch by design, and a project
    that never opens an epoch keeps the legacy row-only behaviour. Once the epoch is
    open this runs in the caller's transaction, beside the registry INSERT, so the row
    and the signed event cannot diverge.

    ``definition`` is ``wf.to_dict()`` minus ``raw_yaml`` — ``RECONCILIATION.md``
    Resolution 2 requires "the complete semantic definition and must not contain
    ``raw_yaml``", and the v6 payload validator rejects it outright.
    """
    import uuid as _uuid

    from ._v6_writer import (
        WORKFLOW_REGISTERED,
        append_v6_event,
        read_project_identity,
        resolve_producer,
        workflow_definition_hash,
    )

    identity = read_project_identity(conn)
    if identity is None:
        return
    if key_set is None:
        raise RegistaError(
            ErrorCode.LOAD_BEARING_FIELD_MISSING,
            "registering a workflow in an opened v6 epoch requires a key set: the "
            "registration is a signed event, not a row (V6-ENVELOPE.md §1.9)",
            detail={"fields": ["key_set"]},
        )
    definition = {k: v for k, v in wf.to_dict().items() if k != "raw_yaml"}
    workflow_id = _uuid.uuid5(
        _uuid.NAMESPACE_OID,
        "regista.workflow:"
        + str(identity.project_instance_id)
        + f":{wf.name}:{wf.version}",
    )
    append_v6_event(
        conn,
        key_set,
        entity_kind="workflow",
        entity_id=workflow_id,
        transition=WORKFLOW_REGISTERED,
        actor_id=identity.principal_id,
        actor_kind="system",
        producer=resolve_producer(),
        payload={
            "type": "regista.workflow-registration",
            "version": 1,
            "name": wf.name,
            "workflow_version": wf.version,
            "definition": definition,
            "definition_hash": workflow_definition_hash(definition),
            "supersedes_registration_event_hash": None,
        },
    )


def register_workflow(
    mgr: ConnectionManager,
    metrics: Metrics,
    project: str,
    yaml_content: str,
    *,
    key_set: Any = None,
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

            row = cast(
                dict[str, Any],
                conn.execute(
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
                ).fetchone(),
            )
            # P1.7 admission gate 1: in the v6 epoch a registry ROW is not a
            # registration. Once genesis has opened the epoch, the row is
            # accompanied by a signed `workflow_registered` event in the SAME
            # transaction — so the two cannot diverge, and an event naming this
            # workflow has something to point `registration_event_hash` at.
            #
            # Gated on genesis rather than unconditional: before genesis the v6
            # writer refuses by design, and a project that never opens an epoch
            # keeps the legacy row-only behaviour.
            _append_workflow_registration_event(conn, key_set, wf)

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
    mgr: ConnectionManager,
    metrics: Metrics,
    project: str,
    parse_workflow_yaml: Any,
    yaml_dump: Any,
    path: str | Path,
    *,
    key_set: Any = None,
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
    return register_workflow(mgr, metrics, project, composed_yaml, key_set=key_set)


def get_workflow(
    mgr: ConnectionManager,
    project: str,
    workflow_name: str,
    version: int,
) -> WorkflowDefinition:
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
