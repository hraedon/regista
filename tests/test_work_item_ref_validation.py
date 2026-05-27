from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")

REF_WORKFLOW_YAML = """\
name: ref_test
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: source
    custom_fields:
      - name: name
        type: string
        required: true
  - name: consumer
    custom_fields:
      - name: source_ref
        type: work_item_ref
        target_work_item_type: source
        required: true
      - name: optional_ref
        type: work_item_ref
        target_work_item_type: source
  - name: untyped_ref_holder
    custom_fields:
      - name: any_ref
        type: work_item_ref

link_types: []

attempt_threshold: 3
"""


@pytest.fixture(scope="function")
def regista():
    from regista import Regista

    project = f"test_wir_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow(REF_WORKFLOW_YAML)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestWorkItemRefCreateValidation:
    def test_nonexistent_uuid_rejected(self, regista):
        fake_uuid = str(uuid.uuid4())
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="ref_test",
                work_item_type="consumer",
                actor_id="a1",
                custom_fields={"source_ref": fake_uuid},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION
        assert "nonexistent" in str(exc_info.value)

    def test_wrong_type_rejected(self, regista):
        src, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-1"},
        )
        consumer, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="consumer",
            actor_id="a1",
            custom_fields={"source_ref": str(src.work_item_id)},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="ref_test",
                work_item_type="consumer",
                actor_id="a1",
                custom_fields={"source_ref": str(consumer.work_item_id)},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION
        assert "expected 'source'" in str(exc_info.value)

    def test_correct_type_accepted(self, regista):
        src, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-1"},
        )
        consumer, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="consumer",
            actor_id="a1",
            custom_fields={"source_ref": str(src.work_item_id)},
        )
        assert consumer.custom_fields["source_ref"] == str(src.work_item_id)

    def test_invalid_uuid_format_rejected(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="ref_test",
                work_item_type="consumer",
                actor_id="a1",
                custom_fields={"source_ref": "not-a-uuid"},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION
        assert "invalid UUID" in str(exc_info.value)

    def test_optional_ref_with_none_accepted(self, regista):
        src, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-1"},
        )
        consumer, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="consumer",
            actor_id="a1",
            custom_fields={
                "source_ref": str(src.work_item_id),
                "optional_ref": None,
            },
        )
        assert consumer.custom_fields.get("optional_ref") is None

    def test_untyped_ref_accepts_any_existing_uuid(self, regista):
        src, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-1"},
        )
        holder, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="untyped_ref_holder",
            actor_id="a1",
            custom_fields={"any_ref": str(src.work_item_id)},
        )
        assert holder.custom_fields["any_ref"] == str(src.work_item_id)

    def test_untyped_ref_rejects_nonexistent(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="ref_test",
                work_item_type="untyped_ref_holder",
                actor_id="a1",
                custom_fields={"any_ref": str(uuid.uuid4())},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION


class TestWorkItemRefTransitionValidation:
    def test_transition_rejects_nonexistent_ref(self, regista):
        src, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-1"},
        )
        consumer, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="consumer",
            actor_id="a1",
            custom_fields={"source_ref": str(src.work_item_id)},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                consumer.work_item_id, "start", "a1",
                actor_metadata={"role": "agent"},
                custom_fields={"optional_ref": str(uuid.uuid4())},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION

    def test_transition_rejects_wrong_type_ref(self, regista):
        src, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-1"},
        )
        consumer, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="consumer",
            actor_id="a1",
            custom_fields={"source_ref": str(src.work_item_id)},
        )
        other_consumer, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="consumer",
            actor_id="a1",
            custom_fields={"source_ref": str(src.work_item_id)},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                consumer.work_item_id, "start", "a1",
                actor_metadata={"role": "agent"},
                custom_fields={"optional_ref": str(other_consumer.work_item_id)},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION
        assert "expected 'source'" in str(exc_info.value)

    def test_transition_accepts_correct_type_ref(self, regista):
        src, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-1"},
        )
        src2, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="source",
            actor_id="a1",
            custom_fields={"name": "src-2"},
        )
        consumer, _ = regista.create_work_item(
            workflow_name="ref_test",
            work_item_type="consumer",
            actor_id="a1",
            custom_fields={"source_ref": str(src.work_item_id)},
        )
        regista.transition(
            consumer.work_item_id, "start", "a1",
            actor_metadata={"role": "agent"},
            custom_fields={"optional_ref": str(src2.work_item_id)},
        )
        updated = regista.get_work_item(consumer.work_item_id)
        assert updated.custom_fields["optional_ref"] == str(src2.work_item_id)


MULTI_TARGET_WORKFLOW_YAML = """\
name: multi_ref_test
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: review
    custom_fields:
      - name: title
        type: string
        required: true
  - name: jury
    custom_fields:
      - name: title
        type: string
        required: true
  - name: revision
    custom_fields:
      - name: upstream
        type: work_item_ref
        target_work_item_types: [review, jury]
        required: true
  - name: no_target_ref_holder
    custom_fields:
      - name: any_ref
        type: work_item_ref

link_types: []

attempt_threshold: 3
"""


@pytest.fixture(params=["postgres", "in_memory"], scope="function")
def multi_target_regista(request):
    if request.param == "postgres":
        from regista import Regista

        project = f"test_wir_multi_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        sub.register_workflow(MULTI_TARGET_WORKFLOW_YAML)
        yield sub
        sub.close()
        drop_project_schema(DSN, project)
    else:
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test")
        sub.register_workflow(MULTI_TARGET_WORKFLOW_YAML)
        yield sub
        sub.close()


class TestMultiTargetWorkItemRefCreateValidation:
    def test_accepts_review_ref(self, multi_target_regista):
        rev, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="review",
            actor_id="a1",
            custom_fields={"title": "rev-1"},
        )
        revision, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="revision",
            actor_id="a1",
            custom_fields={"upstream": str(rev.work_item_id)},
        )
        assert revision.custom_fields["upstream"] == str(rev.work_item_id)

    def test_accepts_jury_ref(self, multi_target_regista):
        jury, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="jury",
            actor_id="a1",
            custom_fields={"title": "jury-1"},
        )
        revision, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="revision",
            actor_id="a1",
            custom_fields={"upstream": str(jury.work_item_id)},
        )
        assert revision.custom_fields["upstream"] == str(jury.work_item_id)

    def test_rejects_wrong_type_ref(self, multi_target_regista):
        rev, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="review",
            actor_id="a1",
            custom_fields={"title": "rev-1"},
        )
        other_revision, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="revision",
            actor_id="a1",
            custom_fields={"upstream": str(rev.work_item_id)},
        )
        with pytest.raises(RegistaError) as exc_info:
            multi_target_regista.create_work_item(
                workflow_name="multi_ref_test",
                work_item_type="revision",
                actor_id="a1",
                custom_fields={"upstream": str(other_revision.work_item_id)},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION
        assert "expected one of" in str(exc_info.value)

    def test_rejects_nonexistent_ref(self, multi_target_regista):
        with pytest.raises(RegistaError) as exc_info:
            multi_target_regista.create_work_item(
                workflow_name="multi_ref_test",
                work_item_type="revision",
                actor_id="a1",
                custom_fields={"upstream": str(uuid.uuid4())},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION
        assert "nonexistent" in str(exc_info.value)

    def test_transition_accepts_matching_type(self, multi_target_regista):
        rev, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="review",
            actor_id="a1",
            custom_fields={"title": "rev-1"},
        )
        jury, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="jury",
            actor_id="a1",
            custom_fields={"title": "jury-1"},
        )
        revision, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="revision",
            actor_id="a1",
            custom_fields={"upstream": str(rev.work_item_id)},
        )
        multi_target_regista.transition(
            revision.work_item_id, "start", "a1",
            actor_metadata={"role": "agent"},
            custom_fields={"upstream": str(jury.work_item_id)},
        )
        updated = multi_target_regista.get_work_item(revision.work_item_id)
        assert updated.custom_fields["upstream"] == str(jury.work_item_id)

    def test_transition_rejects_non_matching_type(self, multi_target_regista):
        rev, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="review",
            actor_id="a1",
            custom_fields={"title": "rev-1"},
        )
        revision, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="revision",
            actor_id="a1",
            custom_fields={"upstream": str(rev.work_item_id)},
        )
        revision2, _ = multi_target_regista.create_work_item(
            workflow_name="multi_ref_test",
            work_item_type="revision",
            actor_id="a1",
            custom_fields={"upstream": str(rev.work_item_id)},
        )
        with pytest.raises(RegistaError) as exc_info:
            multi_target_regista.transition(
                revision.work_item_id, "start", "a1",
                actor_metadata={"role": "agent"},
                custom_fields={"upstream": str(revision2.work_item_id)},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION
        assert "expected one of" in str(exc_info.value)


class TestMultiTargetRegistrationValidation:
    def test_both_singular_and_plural_rejected(self):
        from regista._workflow import parse_and_validate

        yaml_text = """\
name: bad
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: source
    custom_fields:
      - name: ref
        type: work_item_ref
        target_work_item_type: source
        target_work_item_types: [source]

link_types: []
"""
        with pytest.raises(RegistaError) as exc_info:
            parse_and_validate(yaml_text)
        assert exc_info.value.code in (
            ErrorCode.WORKFLOW_VALIDATION_FAILED,
            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
        )

    def test_schema_rejects_both_singular_and_plural(self):
        from regista._workflow import validate_json_schema

        data = {
            "name": "bad",
            "version": 1,
            "regista_version": "0.1.0",
            "states": [
                {"name": "new", "initial": True},
                {"name": "done", "terminal": True},
            ],
            "transitions": [
                {"name": "start", "from": "new", "to": "done", "allowed_roles": ["agent"]}
            ],
            "roles": [{"name": "agent"}],
            "work_item_types": [
                {
                    "name": "source",
                    "custom_fields": [
                        {
                            "name": "ref",
                            "type": "work_item_ref",
                            "target_work_item_type": "source",
                            "target_work_item_types": ["source"],
                        }
                    ],
                }
            ],
            "link_types": [],
        }
        with pytest.raises(RegistaError) as exc_info:
            validate_json_schema(data)
        assert exc_info.value.code == ErrorCode.WORKFLOW_VALIDATION_FAILED

    def test_unknown_type_in_plural_rejected(self):
        from regista._workflow import parse_and_validate

        yaml_text = """\
name: bad
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: holder
    custom_fields:
      - name: ref
        type: work_item_ref
        target_work_item_types: [nonexistent]

link_types: []
"""
        with pytest.raises(RegistaError) as exc_info:
            parse_and_validate(yaml_text)
        assert exc_info.value.code == ErrorCode.WORKFLOW_SEMANTIC_ERROR
        assert "unknown work_item_types" in str(exc_info.value)

    def test_plural_form_round_trips_to_dict(self):
        from regista._workflow import parse_and_validate

        yaml_text = """\
name: rt
version: 1
regista_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: review
    custom_fields: []
  - name: jury
    custom_fields: []
  - name: holder
    custom_fields:
      - name: ref
        type: work_item_ref
        target_work_item_types: [review, jury]

link_types: []
"""
        wf = parse_and_validate(yaml_text)
        holder = next(t for t in wf.work_item_types if t.name == "holder")
        ref_field = holder.custom_fields[0]
        assert ref_field.target_work_item_types == ["review", "jury"]
        assert ref_field.target_work_item_type is None
        d = ref_field.to_dict()
        assert d["target_work_item_types"] == ["review", "jury"]
        assert "target_work_item_type" not in d
        from regista._types import CustomFieldDef
        round_tripped = CustomFieldDef.from_dict(d)
        assert round_tripped.target_work_item_types == ["review", "jury"]
