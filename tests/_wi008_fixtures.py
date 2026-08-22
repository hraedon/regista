"""Shared v6 fixtures for WI-008 action-delegation integration tests."""

from __future__ import annotations

import base64
import copy
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from regista._datetime_utils import v6_occurred_at
from regista._jcs import canonicalize
from tests._v6_fixtures import (
    Producer,
    accept_key,
    make_v6_keyset,
    set_v6_producer_env,
    write_test_genesis,
)

ACTION_ISSUER = "human:delegating-owner"
ACTION_SUBJECT = "agent:delegated-worker"
ACTION_AUTHOR = "agent:author"
ACTION_REVIEWER = "agent:reviewer"
ACTION_REVIEW_ISSUER = "human:review-issuer"
ACTION_FINAL_ACCEPTOR = "human:final-acceptor"

ACTION_PRINCIPALS = (ACTION_ISSUER, ACTION_SUBJECT)
REVIEW_PRINCIPALS = (ACTION_AUTHOR, ACTION_REVIEWER, ACTION_REVIEW_ISSUER)

ACTION_WORKFLOW = """\
name: wi008_action_delegation
version: 1
regista_version: "0.6.0"

states:
  - name: open
    initial: true
  - name: done
    terminal: true

transitions:
  - name: delegated_transition
    from: open
    to: done

roles: []

work_item_types:
  - name: item
    custom_fields: []

link_types: []
"""

REVIEW_WORKFLOW = """\
name: wi008_review
version: 1
regista_version: "0.6.0"

states:
  - name: open
    initial: true
  - name: in_progress
  - name: in_review
  - name: done
    terminal: true

transitions:
  - name: start
    from: open
    to: in_progress
  - name: submit_for_review
    from: in_progress
    to: in_review
  - name: adversarial_pass
    from: in_review
    to: done
    validator: adversarial_review

roles: []

work_item_types:
  - name: item
    custom_fields: []

link_types: []
"""

TWO_STAGE_REVIEW_WORKFLOW = """\
name: wi008_two_stage_review
version: 1
regista_version: "0.6.0"

states:
  - name: open
    initial: true
  - name: in_progress
  - name: in_review
  - name: post_review
  - name: done
    terminal: true

transitions:
  - name: start
    from: open
    to: in_progress
  - name: submit_for_review
    from: in_progress
    to: in_review
  - name: adversarial_pass
    from: in_review
    to: post_review
    validator: adversarial_review
  - name: accept
    from: post_review
    to: done
    validator: human_gate
    validator_params:
      require_human: true

roles: []

work_item_types:
  - name: item
    custom_fields: []

link_types: []
"""


@dataclass(frozen=True)
class ActionProject:
    """A v6 project with accepted actor keys and one work item."""

    instance: Any
    keyset: Any
    genesis: Any
    acceptances: dict[str, Any]
    work_item: Any
    workflow_name: str


def prepare_action_project(
    instance: Any,
    directory: Path,
    *,
    principals: tuple[str, ...] = ACTION_PRINCIPALS,
    workflow: str = ACTION_WORKFLOW,
    workflow_name: str = "wi008_action_delegation",
    creator: str = ACTION_SUBJECT,
) -> ActionProject:
    """Open a clean epoch and return the acceptance anchors by principal.

    ``write_test_genesis`` and ``accept_key`` are the canonical v6 fixture
    helpers.  Keeping the acceptance events in the return value is important:
    a credential must point at the issuer's actual project-chain acceptance,
    not at a key-file assertion or a synthetic event.
    """

    keyset = make_v6_keyset(directory, principals=principals)
    return _prepare_action_project(
        instance,
        keyset,
        principals=principals,
        workflow=workflow,
        workflow_name=workflow_name,
        creator=creator,
    )


def _prepare_action_project(
    instance: Any,
    keyset: Any,
    *,
    principals: tuple[str, ...],
    workflow: str,
    workflow_name: str,
    creator: str,
) -> ActionProject:
    set_v6_producer_env(
        Producer(
            harness="claude-code",
            harness_version="test-harness/1",
            model="claude-fable-5",
            model_lineage="fable",
        ),
        overwrite=True,
    )
    genesis = write_test_genesis(instance, keyset)
    acceptances = {
        principal: accept_key(instance, keyset, genesis, principal)
        for principal in principals
    }
    instance.register_workflow(workflow)
    work_item, _ = instance.create_work_item(
        workflow_name,
        "item",
        creator,
        actor_kind="agent",
    )
    return ActionProject(
        instance=instance,
        keyset=keyset,
        genesis=genesis,
        acceptances=acceptances,
        work_item=work_item,
        workflow_name=workflow_name,
    )


def in_memory_action_project(
    directory: Path,
    *,
    project: str = "wi008_action_delegation",
    principals: tuple[str, ...] = ACTION_PRINCIPALS,
    workflow: str = ACTION_WORKFLOW,
    workflow_name: str = "wi008_action_delegation",
    creator: str = ACTION_SUBJECT,
) -> ActionProject:
    from regista.testing import InMemoryRegista

    keyset = make_v6_keyset(directory, principals=principals)
    instance = InMemoryRegista(project=project, hmac_key_path=keyset.path)
    return _prepare_action_project(
        instance,
        keyset,
        principals=principals,
        workflow=workflow,
        workflow_name=workflow_name,
        creator=creator,
    )


@contextmanager
def postgres_action_project(
    directory: Path,
    *,
    project_prefix: str = "wi008_action_delegation",
    principals: tuple[str, ...] = ACTION_PRINCIPALS,
    workflow: str = ACTION_WORKFLOW,
    workflow_name: str = "wi008_action_delegation",
    creator: str = ACTION_SUBJECT,
) -> Iterator[ActionProject]:
    from _helpers import DSN

    from regista import Regista
    from regista.testing import drop_project_schema

    keyset = make_v6_keyset(directory, principals=principals)
    project = f"{project_prefix}_{uuid.uuid4().hex[:8]}"
    instance = Regista.create_project(DSN, project, keyset.path)
    try:
        yield _prepare_action_project(
            instance,
            keyset,
            principals=principals,
            workflow=workflow,
            workflow_name=workflow_name,
            creator=creator,
        )
    finally:
        instance.close()
        drop_project_schema(DSN, project)


def action_delegation_document(
    project: ActionProject,
    *,
    issuer: str = ACTION_ISSUER,
    subject: str = ACTION_SUBJECT,
    transition: str = "note_added",
    workflow_name: str | None = None,
    now: datetime | None = None,
    parent_credential_hash: str | None = None,
    delegation_allowed: bool = False,
    max_uses: int | None = None,
    scope: dict[str, list[str]] | None = None,
    credential_id: str | None = None,
    entity_kind: str = "work_item",
) -> dict[str, Any]:
    """Sign a credential against an actual issuer acceptance in ``project``."""

    import nacl.signing

    issuer_key = project.keyset.key_for(issuer)
    acceptance = project.acceptances[issuer]
    current = now or datetime.now(UTC)
    unsigned: dict[str, Any] = {
        "type": "regista.action-delegation",
        "version": 1,
        "credential_id": credential_id or str(uuid.uuid4()),
        "trust_domain_id": str(project.genesis.trust_domain_id),
        "issuer_principal_id": issuer,
        "subject_principal_id": subject,
        "issuer_key_id": issuer_key.key_id,
        "issuer_key_binding_event_hash": "sha256:" + acceptance.event_hash.hex(),
        "parent_credential_hash": parent_credential_hash,
        "scope": scope
        or {
            "project_instance_ids": [str(project.genesis.project_instance_id)],
            "entity_kinds": [entity_kind],
            "workflow_names": (
                [] if entity_kind == "note" else [workflow_name or project.workflow_name]
            ),
            "transitions": [transition],
        },
        "not_before": v6_occurred_at(current - timedelta(hours=1)),
        "not_after": v6_occurred_at(current + timedelta(hours=1)),
        "max_uses": max_uses,
        "delegation_allowed": delegation_allowed,
    }
    unsigned_bytes = canonicalize(unsigned)
    signing_input = (
        b"regista.action-delegation.v1\x00"
        + len(unsigned_bytes).to_bytes(8, "big")
        + unsigned_bytes
    )
    signature = nacl.signing.SigningKey(issuer_key.seed).sign(signing_input).signature
    return {
        **unsigned,
        "signature": {
            "scheme_id": "ed25519",
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def copy_action_delegation_document(document: dict[str, Any]) -> dict[str, Any]:
    """Return a mutation-safe copy for validator/reference assertions."""

    return copy.deepcopy(document)


def set_review_producer() -> None:
    set_v6_producer_env(
        Producer(
            harness="claude-code",
            harness_version="test-harness/1",
            model="kimi-k2.5",
            model_lineage="kimi",
        ),
        overwrite=True,
    )


def review_to_in_review(project: ActionProject) -> None:
    instance = project.instance
    work_item_id = project.work_item.work_item_id
    instance.transition(work_item_id, "start", ACTION_AUTHOR, actor_kind="agent")
    instance.transition(
        work_item_id,
        "submit_for_review",
        ACTION_AUTHOR,
        actor_kind="agent",
    )
