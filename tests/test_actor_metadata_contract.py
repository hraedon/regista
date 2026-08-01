from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from regista import ActorMetadata, Event, Regista

TESTS_DIR = Path(__file__).parent


class TestActorMetadataDataclass:
    def test_roundtrip_all_fields(self):
        am = ActorMetadata(
            role="interface_architect",
            channel="chat",
            model="claude-sonnet",
            family="anthropic",
            gate_name="interface_spec_syntax",
            attempt_n=2,
            context_hash="sha256:abc123",
            prompt_template_hash="sha256:def456",
        )
        d = am.to_dict()
        assert d == {
            "role": "interface_architect",
            "channel": "chat",
            "model": "claude-sonnet",
            "family": "anthropic",
            "gate_name": "interface_spec_syntax",
            "attempt_n": 2,
            "context_hash": "sha256:abc123",
            "prompt_template_hash": "sha256:def456",
        }
        restored = ActorMetadata.from_dict(d)
        assert restored == am

    def test_partial_fields(self):
        am = ActorMetadata(role="agent", model="gpt-4")
        d = am.to_dict()
        assert d == {"role": "agent", "model": "gpt-4"}
        assert "channel" not in d
        assert "prompt_template_hash" not in d

    def test_empty_dict(self):
        am = ActorMetadata()
        assert am.to_dict() == {}
        assert ActorMetadata.from_dict({}) == am

    def test_prompt_template_hash_roundtrip(self):
        am = ActorMetadata(prompt_template_hash="sha256:xyz789")
        d = am.to_dict()
        assert d == {"prompt_template_hash": "sha256:xyz789"}
        assert ActorMetadata.from_dict(d) == am

    def test_prompt_template_hash_absent_from_dict(self):
        am = ActorMetadata(role="agent")
        d = am.to_dict()
        assert "prompt_template_hash" not in d
        restored = ActorMetadata.from_dict(d)
        assert restored.prompt_template_hash is None

    def test_model_lineage_roundtrip(self):
        am = ActorMetadata(role="agent", model="gpt-5", model_lineage="gpt-sol")
        d = am.to_dict()
        assert d["model_lineage"] == "gpt-sol"
        assert ActorMetadata.from_dict(d) == am

    def test_model_lineage_absent_from_dict_when_unset(self):
        am = ActorMetadata(role="agent")
        d = am.to_dict()
        assert "model_lineage" not in d
        assert ActorMetadata.from_dict(d).model_lineage is None


def _make_event(actor_metadata):
    return Event(
        event_id=uuid.uuid4(),
        work_item_id=uuid.uuid4(),
        event_seq=1,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=actor_metadata,
        key_id="test-key-001",
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=datetime.now(UTC),
        transition="start",
        payload=None,
        payload_canonical_hash=b"00",
        signature=b"00",
    )


class TestActorMetadataLintHelper:
    def test_catches_event_missing_family(self):
        evt_with_family = _make_event({
            "role": "agent",
            "channel": "chat",
            "model": "gpt-4",
            "family": "openai",
            "attempt_n": 1,
            "context_hash": "abc",
        })
        evt_missing_family = _make_event({
            "role": "agent",
            "channel": "chat",
            "model": "gpt-4",
            "attempt_n": 1,
            "context_hash": "abc",
        })
        incomplete = Regista.actor_metadata_complete(
            [evt_with_family, evt_missing_family],
            expected_keys=["role", "channel", "model", "family", "attempt_n", "context_hash"],
        )
        assert len(incomplete) == 1
        assert incomplete[0].event_id == evt_missing_family.event_id

    def test_catches_null_metadata(self):
        evt = _make_event(None)
        incomplete = Regista.actor_metadata_complete(
            [evt],
            expected_keys=["role"],
        )
        assert len(incomplete) == 1
