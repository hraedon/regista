from __future__ import annotations

from pathlib import Path

from substrate import ValidationResult, validate_yaml

WORKFLOW_PATH = Path(__file__).parent / "test_workflow.yaml"
WORKFLOW_YAML = WORKFLOW_PATH.read_text()


class TestValidateYamlValid:
    def test_valid_yaml_from_string(self):
        result = validate_yaml(WORKFLOW_YAML)
        assert result.valid
        assert result.errors == []
        assert result.workflow is not None
        assert result.workflow.name == "test_workflow"

    def test_valid_yaml_from_path(self):
        result = validate_yaml(WORKFLOW_PATH)
        assert result.valid
        assert result.workflow is not None
        assert result.workflow.name == "test_workflow"

    def test_valid_yaml_from_path_string_is_content(self):
        result = validate_yaml(str(WORKFLOW_PATH))
        assert not result.valid
        assert any(
            "dict" in e.message.lower()
            or "object" in e.message.lower()
            or "root" in e.message.lower()
            for e in result.errors
        )


class TestValidateYamlInvalidYaml:
    def test_invalid_yaml_syntax(self):
        result = validate_yaml("name: [\n  invalid")
        assert not result.valid
        assert len(result.errors) == 1
        assert "YAML syntax error" in result.errors[0].message


class TestValidateYamlSchemaErrors:
    def test_missing_name(self):
        bad = WORKFLOW_YAML.replace("name: test_workflow", "")
        result = validate_yaml(bad)
        assert not result.valid
        assert any("name" in e.message.lower() or "'name'" in e.message for e in result.errors)

    def test_missing_states(self):
        bad_yaml = """
name: bad_wf
version: 1
substrate_version: "0.1.0"
states: []
transitions: []
roles: []
work_item_types: []
link_types: []
"""
        result = validate_yaml(bad_yaml)
        assert not result.valid
        assert any("initial" in e.message.lower() for e in result.errors)


class TestValidateYamlSemanticErrors:
    def test_unreachable_state(self):
        bad_yaml = """
name: bad_wf
version: 1
substrate_version: "0.1.0"
states:
  - name: start
    initial: true
  - name: end
    terminal: true
  - name: orphan
transitions:
  - name: go
    from: start
    to: end
roles: []
work_item_types: []
link_types: []
"""
        result = validate_yaml(bad_yaml)
        assert not result.valid
        assert any("Unreachable" in e.message for e in result.errors)

    def test_undeclared_role_in_transition(self):
        bad_yaml = """
name: bad_wf
version: 1
substrate_version: "0.1.0"
states:
  - name: start
    initial: true
  - name: end
    terminal: true
transitions:
  - name: go
    from: start
    to: end
    allowed_roles: [nonexistent_role]
roles: []
work_item_types: []
link_types: []
"""
        result = validate_yaml(bad_yaml)
        assert not result.valid
        assert any("undeclared role" in e.message for e in result.errors)


class TestValidateYamlResultShape:
    def test_validation_result_to_dict(self):
        result = validate_yaml(WORKFLOW_YAML)
        d = result.to_dict()
        assert d["valid"] is True
        assert d["errors"] == []
        assert d["workflow"]["name"] == "test_workflow"

    def test_invalid_result_to_dict(self):
        result = validate_yaml("name: [\n  invalid")
        d = result.to_dict()
        assert d["valid"] is False
        assert len(d["errors"]) == 1
        assert "workflow" not in d

    def test_roundtrip_from_dict(self):
        result = validate_yaml(WORKFLOW_YAML)
        d = result.to_dict()
        restored = ValidationResult.from_dict(d)
        assert restored.valid == result.valid
        assert len(restored.errors) == len(result.errors)
        assert restored.workflow.name == result.workflow.name
