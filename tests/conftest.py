from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from regista import Regista
from regista._actor_roles import register_actor_role
from regista._testing import drop_project_schema, raw_transaction

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)

WORKFLOW_NAME = "kernel_workflow"
WORKFLOW_VERSION = 1

WORKFLOW_YAML = """\
name: kernel_workflow
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: in_progress
  - name: review
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: in_progress
    allowed_roles: [agent]
  - name: submit_review
    from: in_progress
    to: review
    allowed_roles: [agent]
  - name: request_changes
    from: review
    to: in_progress
    allowed_roles: [reviewer]
  - name: approve
    from: review
    to: done
    allowed_roles: [reviewer]

roles:
  - name: agent
  - name: reviewer

work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true
        ui_visible: true
      - name: priority
        type: enum
        enum_values: [low, medium, high]
        ui_visible: true
      - name: metadata
        type: json
        ui_visible: false
  - name: bug
    custom_fields:
      - name: severity
        type: enum
        enum_values: [minor, major, critical]
        required: true

link_types:
  - name: blocks
    source_type: feature
    target_type: feature
  - name: fixes
    source_type: feature
    target_type: bug

attempt_threshold: 3
"""


@pytest.fixture
def workflow_yaml() -> str:
    return WORKFLOW_YAML


@pytest.fixture
def project() -> Iterator[str]:
    name = "kernel_test_" + uuid.uuid4().hex[:8]
    try:
        yield name
    finally:
        drop_project_schema(DSN, name)


@pytest.fixture
def sub(project: str, workflow_yaml: str) -> Iterator[Regista]:
    handle = Regista.create_project(DSN, project)
    handle.register_workflow(workflow_yaml)
    try:
        yield handle
    finally:
        handle.close()


@pytest.fixture
def strict_sub(project: str, sub: Regista) -> Iterator[Regista]:
    handle = Regista(DSN, project, strict_roles=True)
    try:
        yield handle
    finally:
        handle.close()


@pytest.fixture
def register_role(sub: Regista) -> Callable[[str, str], None]:
    def _register(actor_id: str, role: str) -> None:
        with raw_transaction(sub) as conn:
            register_actor_role(conn, actor_id, role)

    return _register


@pytest.fixture
def agent_meta() -> dict[str, Any]:
    return {"role": "agent"}


@pytest.fixture
def reviewer_meta() -> dict[str, Any]:
    return {"role": "reviewer"}


@pytest.fixture
def make_feature(sub: Regista) -> Callable[..., Any]:
    def _make(actor: str = "alice", **overrides: Any) -> Any:
        fields: dict[str, Any] = {"title": "a feature", "priority": "low", "metadata": {}}
        fields.update(overrides)
        wi, _evt = sub.create_work_item(
            WORKFLOW_NAME, "feature", actor, custom_fields=fields
        )
        return wi

    return _make


@pytest.fixture
def make_bug(sub: Regista) -> Callable[..., Any]:
    def _make(actor: str = "alice", **overrides: Any) -> Any:
        fields: dict[str, Any] = {"severity": "minor"}
        fields.update(overrides)
        wi, _evt = sub.create_work_item(
            WORKFLOW_NAME, "bug", actor, custom_fields=fields
        )
        return wi

    return _make
