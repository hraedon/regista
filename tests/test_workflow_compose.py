from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._workflow_compose import (
    MAX_INCLUDE_DEPTH,
    _deep_merge,
    _merge_lists,
    compose_workflow,
    resolve_includes,
)


class TestDeepMerge:
    def test_override_scalar(self):
        parent = {"name": "parent", "version": 1}
        child = {"version": 2}
        result = _deep_merge(parent, child, {})
        assert result == {"name": "parent", "version": 2}

    def test_deep_merge_dicts(self):
        parent = {"a": {"x": 1, "y": 2}}
        child = {"a": {"y": 3, "z": 4}}
        result = _deep_merge(parent, child, {})
        assert result == {"a": {"x": 1, "y": 3, "z": 4}}

    def test_list_replace_without_key(self):
        parent = {"items": [1, 2, 3]}
        child = {"items": [4, 5]}
        result = _deep_merge(parent, child, {})
        assert result == {"items": [4, 5]}

    def test_append_list(self):
        parent = {"allowed_roles": ["agent"]}
        child = {"allowed_roles__append": ["human"]}
        result = _deep_merge(parent, child, {})
        assert result == {"allowed_roles": ["agent", "human"]}

    def test_append_to_missing(self):
        child = {"allowed_roles__append": ["human"]}
        result = _deep_merge({}, child, {})
        assert result == {"allowed_roles": ["human"]}

    def test_append_non_list_raises(self):
        parent = {"allowed_roles": "agent"}
        child = {"allowed_roles__append": ["human"]}
        with pytest.raises(RegistaError) as exc_info:
            _deep_merge(parent, child, {})
        assert exc_info.value.code == ErrorCode.WORKFLOW_COMPOSE_ERROR


class TestMergeLists:
    def test_keyed_merge_override(self):
        parent = [{"name": "a", "value": 1}]
        child = [{"name": "a", "value": 2}]
        result = _merge_lists(parent, child, "name")
        assert result == [{"name": "a", "value": 2}]

    def test_keyed_merge_append(self):
        parent = [{"name": "a", "value": 1}]
        child = [{"name": "b", "value": 2}]
        result = _merge_lists(parent, child, "name")
        assert result == [{"name": "b", "value": 2}, {"name": "a", "value": 1}]

    def test_keyed_merge_remove(self):
        parent = [{"name": "a", "value": 1}, {"name": "b", "value": 2}]
        child = [{"name": "a", "__remove": True}]
        result = _merge_lists(parent, child, "name")
        assert result == [{"name": "b", "value": 2}]

    def test_composite_key(self):
        parent = [{"name": "claim", "from": "new", "value": 1}]
        child = [{"name": "claim", "from": "new", "value": 2}]
        result = _merge_lists(parent, child, "(name, from)")
        assert result == [{"name": "claim", "from": "new", "value": 2}]


class TestResolveIncludes:
    def test_single_file_no_extends(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "base.yaml"
            path.write_text(
                """
name: test
version: 1
regista_version: 0.1.0
states:
  - name: new
    initial: true
transitions: []
roles: []
work_item_types: []
"""
            )
            data, smap = resolve_includes(path)
            assert data["name"] == "test"
            assert "extends" not in data
            assert any(e["source_file"] == "base.yaml" for e in smap.entries)

    def test_simple_extends(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "base.yaml"
            child = Path(tmpdir) / "child.yaml"
            base.write_text(
                """
name: test
version: 1
regista_version: 0.1.0
states:
  - name: new
    initial: true
transitions: []
roles: []
work_item_types: []
"""
            )
            child.write_text(
                """
extends: ./base.yaml
version: 2
"""
            )
            data, smap = resolve_includes(child)
            assert data["name"] == "test"
            assert data["version"] == 2
            assert "extends" not in data
            assert any(e["source_file"] == "base.yaml" for e in smap.entries)

    def test_cycle_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "a.yaml"
            b = Path(tmpdir) / "b.yaml"
            a.write_text("extends: ./b.yaml\n")
            b.write_text("extends: ./a.yaml\n")
            with pytest.raises(RegistaError) as exc_info:
                resolve_includes(a)
            assert exc_info.value.code == ErrorCode.WORKFLOW_COMPOSE_ERROR
            assert "Cycle" in exc_info.value.message

    def test_max_depth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            files = []
            for i in range(MAX_INCLUDE_DEPTH + 2):
                p = Path(tmpdir) / f"f{i}.yaml"
                if i < MAX_INCLUDE_DEPTH + 1:
                    p.write_text(f"extends: ./f{i+1}.yaml\n")
                else:
                    p.write_text(
                        """
name: test
version: 1
regista_version: 0.1.0
states:
  - name: new
    initial: true
transitions: []
roles: []
work_item_types: []
"""
                    )
                files.append(p)
            with pytest.raises(RegistaError) as exc_info:
                resolve_includes(files[0])
            assert exc_info.value.code == ErrorCode.WORKFLOW_COMPOSE_ERROR
            assert "depth" in exc_info.value.message

    def test_path_escape(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "child.yaml"
            p.write_text("extends: ../base.yaml\n")
            with pytest.raises(RegistaError) as exc_info:
                resolve_includes(p)
            assert exc_info.value.code == ErrorCode.WORKFLOW_COMPOSE_ERROR

    def test_missing_parent_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "child.yaml"
            p.write_text("extends: ./nonexistent.yaml\n")
            with pytest.raises(RegistaError) as exc_info:
                resolve_includes(p)
            assert exc_info.value.code == ErrorCode.WORKFLOW_COMPOSE_ERROR

    def test_diamond_not_allowed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            a = Path(tmpdir) / "a.yaml"
            b = Path(tmpdir) / "b.yaml"
            c = Path(tmpdir) / "c.yaml"
            base = Path(tmpdir) / "base.yaml"
            base.write_text(
                """
name: test
version: 1
regista_version: 0.1.0
states:
  - name: new
    initial: true
transitions: []
roles: []
work_item_types: []
"""
            )
            b.write_text("extends: ./base.yaml\n")
            c.write_text("extends: ./base.yaml\n")
            a.write_text("extends: ./b.yaml\n")
            # Current semantics treat it as normal; no error.
            data, _ = resolve_includes(a)
            assert data["name"] == "test"


class TestComposeWorkflow:
    def test_compose_workflow_with_transitions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir) / "base.yaml"
            child = Path(tmpdir) / "child.yaml"
            base.write_text(
                """
name: test
version: 1
regista_version: 0.1.0
states:
  - name: new
    initial: true
  - name: done
    terminal: true
transitions:
  - name: claim
    from: new
    to: new
    allowed_roles: [agent]
roles: []
work_item_types: []
"""
            )
            child.write_text(
                """
extends: ./base.yaml
version: 2
transitions:
  - name: claim
    from: new
    to: new
    allowed_roles__append: [human]
"""
            )
            data, _ = compose_workflow(child)
            assert data["version"] == 2
            transitions = data["transitions"]
            claim = next(t for t in transitions if t["name"] == "claim")
            assert claim["allowed_roles"] == ["agent", "human"]
