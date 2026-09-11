from __future__ import annotations

import pytest

from regista import RegistaError, validate_yaml
from regista._errors import ErrorCode

_BASE = """\
name: {name}
version: 1
regista_version: "0.1.0"
states:
  - {{name: new, initial: true}}
  - {{name: done, terminal: true}}
transitions:
  - {{name: go, from: new, to: done}}
roles:
  - {{name: agent}}
work_item_types:
  - {{name: task, custom_fields: []}}
"""


def test_validate_yaml_accepts_fixture(workflow_yaml: str) -> None:
    result = validate_yaml(workflow_yaml)
    assert result.valid is True
    assert result.errors == []
    assert result.workflow is not None
    assert result.workflow.name == "kernel_workflow"


def test_register_workflow_round_trip(sub, workflow_yaml: str) -> None:
    version = sub.register_workflow(workflow_yaml)
    assert version.name == "kernel_workflow"
    assert version.version == 1
    assert version.regista_version == "0.1.0"

    definition = sub.get_workflow("kernel_workflow", 1)
    assert definition.name == "kernel_workflow"
    assert definition.initial_state == "new"
    assert definition.terminal_states == ["done"]
    assert {"start", "submit_review", "request_changes", "approve"} == {
        t.name for t in definition.transitions
    }
    assert definition.attempt_threshold == 3


def test_reregister_identical_is_idempotent(sub, workflow_yaml: str) -> None:
    first = sub.register_workflow(workflow_yaml)
    second = sub.register_workflow(workflow_yaml)
    assert first.name == second.name
    assert first.version == second.version


def test_same_version_different_content_conflicts(sub, workflow_yaml: str) -> None:
    modified = workflow_yaml.replace("attempt_threshold: 3", "attempt_threshold: 5")
    assert modified != workflow_yaml
    with pytest.raises(RegistaError) as exc:
        sub.register_workflow(modified)
    assert exc.value.code is ErrorCode.WORKFLOW_VERSION_CONFLICT


@pytest.mark.parametrize(
    "raw",
    [
        "name: [unclosed",
        "[1, 2, 3]",
        "",
    ],
)
def test_malformed_yaml_is_rejected(raw: str, sub) -> None:
    result = validate_yaml(raw)
    assert result.valid is False
    assert result.errors

    with pytest.raises(RegistaError) as exc:
        sub.register_workflow(raw)
    assert exc.value.code is ErrorCode.WORKFLOW_VALIDATION_FAILED


@pytest.mark.parametrize(
    "raw",
    [
        # duplicate state names
        """\
name: dup_states
version: 1
regista_version: "0.1.0"
states:
  - {name: new, initial: true}
  - {name: new}
  - {name: done, terminal: true}
transitions:
  - {name: go, from: new, to: done}
roles:
  - {name: agent}
work_item_types:
  - {name: task, custom_fields: []}
""",
        # transition references an undeclared role
        """\
name: bad_role
version: 1
regista_version: "0.1.0"
states:
  - {name: new, initial: true}
  - {name: done, terminal: true}
transitions:
  - {name: go, from: new, to: done, allowed_roles: [ghost]}
roles:
  - {name: agent}
work_item_types:
  - {name: task, custom_fields: []}
""",
        # unreachable state
        """\
name: unreachable
version: 1
regista_version: "0.1.0"
states:
  - {name: new, initial: true}
  - {name: done, terminal: true}
  - {name: orphan}
transitions:
  - {name: go, from: new, to: done}
roles:
  - {name: agent}
work_item_types:
  - {name: task, custom_fields: []}
""",
        # dead-end state not declared terminal
        """\
name: dead_end
version: 1
regista_version: "0.1.0"
states:
  - {name: new, initial: true}
  - {name: done}
transitions:
  - {name: go, from: new, to: done}
roles:
  - {name: agent}
work_item_types:
  - {name: task, custom_fields: []}
""",
        # duplicate transitions (same name + from)
        """\
name: dup_transitions
version: 1
regista_version: "0.1.0"
states:
  - {name: new, initial: true}
  - {name: done, terminal: true}
transitions:
  - {name: go, from: new, to: done}
  - {name: go, from: new, to: done}
roles:
  - {name: agent}
work_item_types:
  - {name: task, custom_fields: []}
""",
    ],
)
def test_semantic_errors_are_rejected(raw: str, sub) -> None:
    result = validate_yaml(raw)
    assert result.valid is False
    assert result.errors

    with pytest.raises(RegistaError) as exc:
        sub.register_workflow(raw)
    assert exc.value.code is ErrorCode.WORKFLOW_SEMANTIC_ERROR


def test_reserved_transition_name_is_rejected(sub) -> None:
    raw = _BASE.format(name="reserved").replace(
        "{name: go, from: new, to: done}",
        "{name: created, from: new, to: done}",
    )
    with pytest.raises(RegistaError) as exc:
        sub.register_workflow(raw)
    assert exc.value.code is ErrorCode.RESERVED_TRANSITION_NAME
