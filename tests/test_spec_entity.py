from __future__ import annotations

import hashlib
import uuid

import pytest
from _helpers import DSN

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

SPEC_YAML = """\
name: test-project
version: 1
states:
  - name: new
  - name: done
transitions:
  - name: start
    from: new
    to: done
roles:
  - name: agent
work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true
"""

SPEC_MD = "# Test Project\n\nA test spec."

#: The principals that sign spec events in this file (v6 requires a canonical
#: actor with an accepted key; ``sign_spec`` routes through the v6 writer).
SPEC_SPECIFIER = "human:specifier"
SPEC_AUDITOR = "human:auditor"
SPEC_PRINCIPALS = (SPEC_SPECIFIER, SPEC_AUDITOR)

WORKFLOW_PATH = "tests/test_workflow.yaml"


def _spec_md_hash() -> str:
    return hashlib.sha256(SPEC_MD.encode()).hexdigest()


@pytest.fixture
def spec_project(tmp_path_factory):
    from regista.testing import drop_project_schema

    keyset = make_v6_keyset(
        tmp_path_factory.mktemp("spec_keys"),
        principals=(*SPEC_PRINCIPALS, "agent:worker"),
    )
    project = f"spec_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    try:
        open_v6_epoch(
            sub,
            keyset,
            principals=(*SPEC_PRINCIPALS, "agent:worker"),
            entity_kinds=("work_item", "principal", "workflow", "spec"),
        )
        yield sub
    finally:
        sub.close()
        drop_project_schema(DSN, project)


class TestSignSpecPostgres:
    def test_sign_spec_creates_event(self, spec_project):
        sub = spec_project
        evt = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        assert evt.entity_kind == "spec"
        assert evt.transition == "spec_signed"
        assert evt.payload is not None
        assert evt.payload["spec_yaml"] == SPEC_YAML
        assert evt.payload["spec_md_hash"] == _spec_md_hash()
        assert evt.payload["spec_schema_version"] == "1.0"

    def test_sign_spec_with_explicit_id(self, spec_project):
        sub = spec_project
        spec_id = uuid.uuid4()
        evt = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
            spec_id=spec_id,
        )
        assert evt.effective_entity_id == spec_id

    def test_sign_spec_rejects_empty_yaml(self, spec_project):
        sub = spec_project
        with pytest.raises(RegistaError) as exc:
            sub.sign_spec(
                spec_yaml="",
                spec_md_hash=_spec_md_hash(),
                spec_schema_version="1.0",
                actor_id=SPEC_SPECIFIER,
                actor_kind="human",
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_sign_spec_rejects_empty_version(self, spec_project):
        sub = spec_project
        with pytest.raises(RegistaError) as exc:
            sub.sign_spec(
                spec_yaml=SPEC_YAML,
                spec_md_hash=_spec_md_hash(),
                spec_schema_version="",
                actor_id=SPEC_SPECIFIER,
                actor_kind="human",
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_sign_spec_rejects_empty_md_hash(self, spec_project):
        sub = spec_project
        with pytest.raises(RegistaError) as exc:
            sub.sign_spec(
                spec_yaml=SPEC_YAML,
                spec_md_hash="",
                spec_schema_version="1.0",
                actor_id=SPEC_SPECIFIER,
                actor_kind="human",
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT

    def test_unknown_schema_version_stored_not_rejected(self, spec_project):
        sub = spec_project
        evt = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="999.0-unknown",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        assert evt.entity_kind == "spec"
        assert evt.payload["spec_schema_version"] == "999.0-unknown"

    def test_known_schema_version_no_warning(self, spec_project):
        sub = spec_project
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
            known_spec_schema_versions=frozenset({"1.0"}),
        )

    def test_read_spec_events(self, spec_project):
        sub = spec_project
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="2.0",
            actor_id=SPEC_AUDITOR,
            actor_kind="human",
        )
        events = sub.read_spec_events()
        assert len(events) == 2
        assert all(e.entity_kind == "spec" for e in events)

    def test_read_spec_events_by_spec_id(self, spec_project):
        sub = spec_project
        spec_id = uuid.uuid4()
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
            spec_id=spec_id,
        )
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="2.0",
            actor_id=SPEC_AUDITOR,
            actor_kind="human",
            spec_id=uuid.uuid4(),
        )
        events = sub.read_spec_events(spec_id=spec_id)
        assert len(events) == 1
        assert events[0].effective_entity_id == spec_id

    def test_read_spec_events_empty(self, spec_project):
        sub = spec_project
        events = sub.read_spec_events()
        assert events == []

    def test_spec_event_in_replay(self, spec_project):
        sub = spec_project
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        report = sub.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0

    def test_spec_event_chain_verified(self, spec_project):
        sub = spec_project
        evt = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        assert evt.signature is not None
        assert evt.payload_canonical_hash is not None
        assert evt.prev_event_hash is not None or evt.event_seq == 1
        events = sub.read_spec_events()
        assert len(events) == 1
        assert events[0].event_id == evt.event_id

    def test_multiple_specs_independent_seq(self, spec_project):
        sub = spec_project
        evt1 = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        evt2 = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_AUDITOR,
            actor_kind="human",
        )
        assert evt1.event_seq == 1
        assert evt2.event_seq == 1
        assert evt1.effective_entity_id != evt2.effective_entity_id

    def test_spec_does_not_interfere_with_work_items(self, spec_project):
        sub = spec_project
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            actor_kind="agent",
            custom_fields={"title": "post-spec"},
        )
        assert wi is not None
        report = sub.replay()
        assert report.halted == 0


class TestSignSpecInMemory:
    @pytest.fixture
    def spec_project(self, tmp_path_factory):
        from regista.testing import InMemoryRegista

        keyset = make_v6_keyset(
            tmp_path_factory.mktemp("spec_mem_keys"),
            principals=SPEC_PRINCIPALS,
        )
        instance = InMemoryRegista(
            project="spec_mem", hmac_key_path=keyset.path
        )
        open_v6_epoch(
            instance,
            keyset,
            principals=SPEC_PRINCIPALS,
            entity_kinds=("work_item", "principal", "workflow", "spec"),
        )
        yield instance

    def test_in_memory_sign_spec(self, spec_project):
        sub = spec_project
        evt = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        assert evt.entity_kind == "spec"
        assert evt.transition == "spec_signed"
        assert evt.payload["spec_yaml"] == SPEC_YAML

    def test_in_memory_read_spec_events(self, spec_project):
        sub = spec_project
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="2.0",
            actor_id=SPEC_AUDITOR,
            actor_kind="human",
        )
        events = sub.read_spec_events()
        assert len(events) == 2

    def test_in_memory_unknown_version_stored(self, spec_project):
        sub = spec_project
        evt = sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="unknown-999",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        assert evt.payload["spec_schema_version"] == "unknown-999"

    def test_in_memory_replay_includes_spec(self, spec_project):
        sub = spec_project
        sub.sign_spec(
            spec_yaml=SPEC_YAML,
            spec_md_hash=_spec_md_hash(),
            spec_schema_version="1.0",
            actor_id=SPEC_SPECIFIER,
            actor_kind="human",
        )
        report = sub.replay()
        assert report.halted == 0
